/*
 * Totals POS - Background cloud sync
 * ---------------------------------------------------------------------------
 * The app is fully functional with NO backend at all (pure offline register).
 * When an "API base URL" is configured in Settings, this module:
 *   1. PUSHES the durable outbox (sales, stock deltas, product edits) up to the
 *      cloud so head office sees real-time figures across every register.
 *   2. PULLS server-side changes down (new/edited products, price changes,
 *      renamed or suspended tenants) so an administrator can update a shop
 *      remotely without ever visiting it.
 * All of this retries automatically whenever connectivity returns.
 */
window.Sync = (function () {
  'use strict';

  let running = false;
  let timer = null;
  const listeners = [];

  function onChange(fn) { listeners.push(fn); }
  function emit(state) { listeners.forEach((f) => { try { f(state); } catch (e) {} }); }

  function isOnline() { return navigator.onLine; }
  function configured() { return !!Config.apiBase(); }

  function queue(entity, entityId, op, payload, tenantId) {
    DB.run(
      `INSERT INTO sync_queue(id,tenant_id,entity,entity_id,op,payload,attempts,created_at)
       VALUES(?,?,?,?,?,?,0,?)`,
      [DB.uid('q'), tenantId || Config.activeTenantId(), entity, entityId, op,
       JSON.stringify(payload || {}), DB.nowISO()]
    );
    // Ask the browser to sync in the background even if the app is closed.
    if ('serviceWorker' in navigator && 'SyncManager' in window) {
      navigator.serviceWorker.ready.then((reg) => reg.sync.register('totals-sync')).catch(() => {});
    }
    scheduleSoon();
  }

  function pendingCount() {
    const r = DB.get('SELECT COUNT(*) AS n FROM sync_queue');
    return r ? r.n : 0;
  }

  async function apiFetch(path, opts) {
    const base = Config.apiBase();
    const res = await fetch(base + path, Object.assign({
      headers: { 'Content-Type': 'application/json' }
    }, opts));
    if (!res.ok) throw new Error('HTTP ' + res.status);
    return res.json();
  }

  /* ---------- PUSH: upload the outbox ---------- */
  async function push() {
    const rows = DB.all('SELECT * FROM sync_queue ORDER BY created_at LIMIT 100');
    if (!rows.length) return { pushed: 0 };
    const changes = rows.map((r) => ({
      id: r.id, tenant_id: r.tenant_id, entity: r.entity,
      entity_id: r.entity_id, op: r.op, payload: JSON.parse(r.payload || '{}'),
      created_at: r.created_at
    }));
    const out = await apiFetch('/api/sync', {
      method: 'POST',
      body: JSON.stringify({ device: Config.deviceName(), changes })
    });
    const applied = new Set(out.applied || []);
    rows.forEach((r) => {
      if (applied.has(r.id)) {
        DB.run('DELETE FROM sync_queue WHERE id = ?', [r.id]);
        if (r.entity === 'sale') DB.run('UPDATE sales SET synced = 1 WHERE id = ?', [r.entity_id]);
      } else {
        DB.run('UPDATE sync_queue SET attempts = attempts + 1 WHERE id = ?', [r.id]);
      }
    });
    return { pushed: applied.size };
  }

  /* ---------- PULL: apply remote changes ---------- */
  async function pull() {
    const since = DB.getSetting('sync_cursor') || '';
    const out = await apiFetch('/api/pull?since=' + encodeURIComponent(since), { method: 'GET' });
    (out.tenants || []).forEach(upsertTenant);
    (out.products || []).forEach(upsertProduct);
    (out.variations || []).forEach(upsertVariation);
    (out.staff || []).forEach(upsertStaff);
    if (out.cursor) DB.setSetting('sync_cursor', out.cursor);
    return { pulled: (out.tenants || []).length + (out.products || []).length +
                     (out.variations || []).length + (out.staff || []).length };
  }

  // Upserts apply "last write wins" using updated_at so remote edits win only
  // when they are newer than the local copy.
  function newer(remote, table) {
    const local = DB.get(`SELECT updated_at FROM ${table} WHERE id = ?`, [remote.id]);
    if (!local) return true;
    return String(remote.updated_at || '') > String(local.updated_at || '');
  }
  function upsertTenant(t) {
    if (!newer(t, 'tenants')) return;
    DB.run(`INSERT INTO tenants(id,name,slug,tin,phone,email,address,currency,vat_rate,vat_inclusive,receipt_footer,logo,status,updated_at,created_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
      ON CONFLICT(id) DO UPDATE SET name=excluded.name,slug=excluded.slug,tin=excluded.tin,phone=excluded.phone,
        email=excluded.email,address=excluded.address,currency=excluded.currency,vat_rate=excluded.vat_rate,
        vat_inclusive=excluded.vat_inclusive,receipt_footer=excluded.receipt_footer,logo=excluded.logo,
        status=excluded.status,updated_at=excluded.updated_at`,
      [t.id, t.name, t.slug, t.tin, t.phone, t.email, t.address, t.currency || 'GHS',
       t.vat_rate ?? 15, t.vat_inclusive ?? 1, t.receipt_footer, t.logo, t.status || 'active',
       t.updated_at || DB.nowISO(), t.created_at || DB.nowISO()]);
  }
  function upsertProduct(p) {
    if (!newer(p, 'products')) return;
    DB.run(`INSERT INTO products(id,tenant_id,name,description,category,image,color,active,sort,updated_at,created_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?)
      ON CONFLICT(id) DO UPDATE SET name=excluded.name,description=excluded.description,category=excluded.category,
        image=excluded.image,color=excluded.color,active=excluded.active,sort=excluded.sort,updated_at=excluded.updated_at`,
      [p.id, p.tenant_id, p.name, p.description, p.category || 'General', p.image, p.color,
       p.active ?? 1, p.sort ?? 0, p.updated_at || DB.nowISO(), p.created_at || DB.nowISO()]);
  }
  function upsertVariation(v) {
    if (!newer(v, 'variations')) return;
    DB.run(`INSERT INTO variations(id,product_id,tenant_id,name,sku,barcode,price,cost,stock,track_stock,low_stock_threshold,supplier_id,active,updated_at,created_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
      ON CONFLICT(id) DO UPDATE SET name=excluded.name,sku=excluded.sku,barcode=excluded.barcode,price=excluded.price,
        cost=excluded.cost,stock=excluded.stock,track_stock=excluded.track_stock,low_stock_threshold=excluded.low_stock_threshold,
        supplier_id=excluded.supplier_id,active=excluded.active,updated_at=excluded.updated_at`,
      [v.id, v.product_id, v.tenant_id, v.name, v.sku, v.barcode, v.price, v.cost, v.stock,
       v.track_stock ?? 1, v.low_stock_threshold ?? 5, v.supplier_id, v.active ?? 1,
       v.updated_at || DB.nowISO(), v.created_at || DB.nowISO()]);
  }
  function upsertStaff(s) {
    if (!newer(s, 'staff')) return;
    DB.run(`INSERT INTO staff(id,tenant_id,name,username,pin_hash,salt,role,active,updated_at,created_at)
      VALUES(?,?,?,?,?,?,?,?,?,?)
      ON CONFLICT(id) DO UPDATE SET name=excluded.name,username=excluded.username,pin_hash=excluded.pin_hash,
        salt=excluded.salt,role=excluded.role,active=excluded.active,updated_at=excluded.updated_at`,
      [s.id, s.tenant_id, s.name, (s.username || '').toLowerCase(), s.pin_hash, s.salt,
       s.role || 'cashier', s.active ?? 1, s.updated_at || DB.nowISO(), s.created_at || DB.nowISO()]);
  }

  /* ---------- Orchestration ---------- */
  async function run(force) {
    if (running) return;
    if (!configured()) { emit({ state: 'local-only', pending: pendingCount() }); return; }
    if (!isOnline() && !force) { emit({ state: 'offline', pending: pendingCount() }); return; }
    running = true;
    emit({ state: 'syncing', pending: pendingCount() });
    try {
      await pull();
      await push();
      DB.setSetting('last_sync_at', DB.nowISO());
      DB.persistNow();
      emit({ state: 'synced', pending: pendingCount(), at: DB.getSetting('last_sync_at') });
    } catch (e) {
      emit({ state: 'error', pending: pendingCount(), error: e.message });
    } finally {
      running = false;
    }
  }

  function scheduleSoon() { setTimeout(() => run(false), 800); }

  function start() {
    window.addEventListener('online', () => run(true));
    window.addEventListener('offline', () => emit({ state: 'offline', pending: pendingCount() }));
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.addEventListener('message', (e) => {
        if (e.data && e.data.type === 'RUN_SYNC') run(true);
      });
    }
    clearInterval(timer);
    timer = setInterval(() => run(false), 30000); // periodic catch-up
    run(false);
  }

  return { start, run, queue, pendingCount, onChange, configured, isOnline };
})();
