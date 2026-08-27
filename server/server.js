/*
 * Totals POS - Reference cloud backend
 * ===========================================================================
 * A small, ZERO-DEPENDENCY Node.js server that implements the REST API the
 * Totals POS Progressive Web App syncs against. It is deliberately dependency
 * free (built only on Node's own `http`/`fs`) so it deploys unchanged to
 * Render, Railway, Fly.io, a VPS, or `node server/server.js` on a laptop.
 *
 * What it provides
 * ----------------
 *  - A durable, multi-tenant store (a JSON file; swap for Postgres in prod).
 *  - POST /api/sync   Registers push sales + stock deltas + product edits here.
 *  - GET  /api/pull   Registers pull down remote edits (prices, new items,
 *                     renamed/suspended tenants) so a shop can be updated over
 *                     the web WITHOUT anyone visiting it.
 *  - Admin REST API   Create / rename / suspend tenants centrally.
 *  - GET  /admin      A tiny web control portal for administrators.
 *  - Low-stock alerts Computed on every stock change and exposed at /api/alerts.
 *
 * Every write bumps a global sequence number; /api/pull is cursor based so a
 * register only ever downloads what changed since it last synced.
 */
'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 4000;
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'data.json');
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'change-me-admin-token';

/* ------------------------------- storage -------------------------------- */
function emptyDB() {
  return { seq: 0, tenants: {}, products: {}, variations: {}, sales: {}, sale_items: {}, alerts: [] };
}
let db = emptyDB();
try {
  if (fs.existsSync(DATA_FILE)) db = Object.assign(emptyDB(), JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')));
} catch (e) { console.error('Could not read data file, starting fresh:', e.message); }

let saveTimer = null;
function save() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    fs.writeFile(DATA_FILE, JSON.stringify(db), (e) => { if (e) console.error('save failed', e.message); });
  }, 150);
}
function nowISO() { return new Date().toISOString(); }
function uid(p) { return (p ? p + '_' : '') + crypto.randomUUID(); }
function bump(entity, id) { db.seq += 1; return db.seq; }

/* --------------------------- change application -------------------------- */
function touch(obj) { obj.seq = bump(); obj.updated_at = obj.updated_at || nowISO(); return obj; }

function upsertTenant(t) {
  const cur = db.tenants[t.id] || {};
  db.tenants[t.id] = touch(Object.assign(cur, t, { updated_at: t.updated_at || nowISO() }));
}
function upsertProduct(p) {
  const cur = db.products[p.id] || {};
  db.products[p.id] = touch(Object.assign(cur, p, { updated_at: p.updated_at || nowISO() }));
}
function upsertVariation(v) {
  const cur = db.variations[v.id] || {};
  db.variations[v.id] = touch(Object.assign(cur, v, { updated_at: v.updated_at || nowISO() }));
  checkLowStock(db.variations[v.id]);
}
function checkLowStock(v) {
  if (!v || !v.track_stock) return;
  if (Number(v.stock) <= Number(v.low_stock_threshold || 0)) {
    const existing = db.alerts.find((a) => a.variation_id === v.id && !a.resolved);
    if (!existing) {
      db.alerts.unshift({
        id: uid('alert'), tenant_id: v.tenant_id, variation_id: v.id, sku: v.sku,
        name: v.name, stock: v.stock, threshold: v.low_stock_threshold,
        created_at: nowISO(), resolved: false
      });
      console.log(`[LOW STOCK] tenant=${v.tenant_id} sku=${v.sku} stock=${v.stock}`);
      // Hook: send email/SMS/webhook to trigger reordering here.
    }
  } else {
    db.alerts.forEach((a) => { if (a.variation_id === v.id) a.resolved = true; });
  }
}

// Apply a single change coming from a register's outbox.
function applyChange(ch) {
  const p = ch.payload || {};
  switch (ch.entity) {
    case 'tenant': upsertTenant(Object.assign({ id: ch.entity_id }, p)); break;
    case 'product':
      if (p.product) upsertProduct(p.product);
      (p.variations || []).forEach(upsertVariation);
      if (ch.op === 'delete' && db.products[ch.entity_id]) db.products[ch.entity_id].active = 0;
      break;
    case 'stock': {
      const v = db.variations[ch.entity_id];
      if (v) {
        if (ch.op === 'decrement') v.stock = Number(v.stock) - Number(p.qty || 0);
        else if (ch.op === 'set') v.stock = Number(p.stock || 0);
        touch(v); checkLowStock(v);
      }
      break;
    }
    case 'sale': {
      const s = p.sale || {};
      db.sales[ch.entity_id] = Object.assign({ id: ch.entity_id, received_at: nowISO() }, s);
      (p.items || []).forEach((it) => { const id = uid('si'); db.sale_items[id] = Object.assign({ id, sale_id: ch.entity_id }, it); });
      break;
    }
    default: break;
  }
}

/* ------------------------------ http utils ------------------------------ */
function send(res, code, body, type) {
  res.writeHead(code, {
    'Content-Type': type || 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS'
  });
  res.end(typeof body === 'string' ? body : JSON.stringify(body));
}
function readBody(req) {
  return new Promise((resolve) => {
    let d = ''; req.on('data', (c) => (d += c));
    req.on('end', () => { try { resolve(d ? JSON.parse(d) : {}); } catch (e) { resolve({}); } });
  });
}
function requireAdmin(req) {
  const auth = req.headers['authorization'] || '';
  return auth === 'Bearer ' + ADMIN_TOKEN;
}

/* -------------------------------- routes -------------------------------- */
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;

  if (req.method === 'OPTIONS') return send(res, 204, '');

  // ---- Register push ----
  if (p === '/api/sync' && req.method === 'POST') {
    const body = await readBody(req);
    const applied = [];
    (body.changes || []).forEach((ch) => { try { applyChange(ch); applied.push(ch.id); } catch (e) { console.error('apply failed', e.message); } });
    save();
    return send(res, 200, { applied, low_stock: db.alerts.filter((a) => !a.resolved).length });
  }

  // ---- Register pull (cursor based) ----
  if (p === '/api/pull' && req.method === 'GET') {
    const since = Number(url.searchParams.get('since') || 0);
    const pick = (map) => Object.values(map).filter((x) => (x.seq || 0) > since);
    const tenants = pick(db.tenants), products = pick(db.products), variations = pick(db.variations);
    const cursor = db.seq;
    return send(res, 200, { cursor, tenants, products, variations });
  }

  // ---- Low-stock alerts (reordering) ----
  if (p === '/api/alerts' && req.method === 'GET') {
    const tid = url.searchParams.get('tenant_id');
    const list = db.alerts.filter((a) => !a.resolved && (!tid || a.tenant_id === tid));
    return send(res, 200, { alerts: list });
  }

  // ---- Public tenant list (for register bootstrap) ----
  if (p === '/api/tenants' && req.method === 'GET') {
    return send(res, 200, { tenants: Object.values(db.tenants) });
  }

  // ================= ADMIN API (token protected) =================
  if (p.startsWith('/api/admin/')) {
    if (!requireAdmin(req)) return send(res, 401, { error: 'unauthorized' });

    if (p === '/api/admin/tenants' && req.method === 'GET') {
      return send(res, 200, { tenants: Object.values(db.tenants) });
    }
    if (p === '/api/admin/tenants' && req.method === 'POST') {
      const b = await readBody(req);
      const id = b.id || uid('ten');
      upsertTenant(Object.assign({ id, currency: 'GHS', vat_rate: 15, vat_inclusive: 1, status: 'active', created_at: nowISO() }, b, { id }));
      save();
      return send(res, 200, { tenant: db.tenants[id] });
    }
    const mt = p.match(/^\/api\/admin\/tenants\/([^/]+)$/);
    if (mt && req.method === 'PUT') {
      const id = mt[1]; if (!db.tenants[id]) return send(res, 404, { error: 'not found' });
      const b = await readBody(req);
      upsertTenant(Object.assign({}, db.tenants[id], b, { id, updated_at: nowISO() }));
      save();
      return send(res, 200, { tenant: db.tenants[id] });
    }
    if (mt && req.method === 'DELETE') {
      const id = mt[1]; if (db.tenants[id]) { db.tenants[id].status = 'suspended'; touch(db.tenants[id]); save(); }
      return send(res, 200, { ok: true });
    }
    return send(res, 404, { error: 'unknown admin route' });
  }

  // ---- Web admin portal ----
  if (p === '/admin' || p === '/admin/') {
    return send(res, 200, ADMIN_HTML, 'text/html; charset=utf-8');
  }

  if (p === '/' || p === '/health') {
    return send(res, 200, {
      service: 'Totals POS backend', status: 'ok',
      tenants: Object.keys(db.tenants).length,
      products: Object.keys(db.products).length,
      sales: Object.keys(db.sales).length,
      open_alerts: db.alerts.filter((a) => !a.resolved).length,
      cursor: db.seq
    });
  }

  send(res, 404, { error: 'not found' });
});

/* ----------------------- minimal admin web portal ----------------------- */
const ADMIN_HTML = `<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Totals POS · Admin</title>
<style>
 body{font-family:system-ui;margin:0;background:#0b1220;color:#e8eefc}
 header{padding:14px 18px;background:#16233b;font-weight:700;display:flex;gap:12px;align-items:center}
 main{max-width:900px;margin:0 auto;padding:18px}
 input,button{font:inherit;padding:9px 11px;border-radius:9px;border:1px solid #26324c;background:#1b2740;color:#e8eefc}
 button{cursor:pointer;background:#14b8a6;color:#04211d;font-weight:700;border:none}
 table{width:100%;border-collapse:collapse;margin-top:14px}
 th,td{padding:9px;border-bottom:1px solid #26324c;text-align:left;font-size:14px}
 .card{background:#131c2e;border:1px solid #26324c;border-radius:14px;padding:16px;margin-bottom:16px}
 .row{display:flex;gap:8px;flex-wrap:wrap}
 .muted{color:#93a2c4}.sus{color:#fcd34d}
</style></head><body>
<header>🏢 Totals POS — Admin Control Portal</header>
<main>
 <div class="card">
  <label class="muted">Admin token</label>
  <div class="row"><input id="tok" placeholder="ADMIN_TOKEN" style="flex:1"><button onclick="load()">Connect</button></div>
 </div>
 <div class="card">
  <h3>Create tenant</h3>
  <div class="row">
   <input id="n" placeholder="Business name">
   <input id="tin" placeholder="TIN">
   <input id="ph" placeholder="Phone">
   <button onclick="create()">Create</button>
  </div>
 </div>
 <div class="card">
  <h3>Tenants</h3>
  <table id="t"><thead><tr><th>Name</th><th>TIN</th><th>Status</th><th></th></tr></thead><tbody></tbody></table>
 </div>
</main>
<script>
 const H=()=>({'Content-Type':'application/json','Authorization':'Bearer '+document.getElementById('tok').value});
 async function load(){
   const r=await fetch('/api/admin/tenants',{headers:H()});
   if(!r.ok){alert('Unauthorized');return;}
   const {tenants}=await r.json();
   document.querySelector('#t tbody').innerHTML=tenants.map(function(x){
     return '<tr><td>'+x.name+'</td><td>'+(x.tin||'')+'</td><td class="'+(x.status==='suspended'?'sus':'')+'">'+(x.status||'active')+
     '</td><td><button onclick="ren(\\''+x.id+'\\',\\''+(x.name||'').replace(/'/g,"")+'\\')">Rename</button> '+
     '<button onclick="sus(\\''+x.id+'\\')">'+(x.status==='suspended'?'Activate':'Suspend')+'</button></td></tr>';
   }).join('');
 }
 async function create(){
   await fetch('/api/admin/tenants',{method:'POST',headers:H(),body:JSON.stringify({name:n.value,tin:tin.value,phone:ph.value})});
   n.value=tin.value=ph.value='';load();
 }
 async function ren(id,cur){ const name=prompt('New name',cur); if(name==null)return;
   await fetch('/api/admin/tenants/'+id,{method:'PUT',headers:H(),body:JSON.stringify({name:name})});load(); }
 async function sus(id){ const cur=await (await fetch('/api/admin/tenants',{headers:H()})).json();
   const t=cur.tenants.find(function(x){return x.id===id;});
   await fetch('/api/admin/tenants/'+id,{method:'PUT',headers:H(),body:JSON.stringify({status:t.status==='suspended'?'active':'suspended'})});load(); }
</script>
</body></html>`;

server.listen(PORT, () => {
  console.log('Totals POS backend listening on :' + PORT);
  console.log('  Admin portal:  http://localhost:' + PORT + '/admin');
  console.log('  Data file:     ' + DATA_FILE);
  if (ADMIN_TOKEN === 'change-me-admin-token') console.warn('  ⚠  Set ADMIN_TOKEN env var before deploying!');
});
