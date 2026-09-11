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
  // Per-table cursors (each table has its own bigserial), stored as JSON. This
  // is robust and also pulls SALES + SALE_ITEMS so every device sees the whole
  // shop, not just what it rang up itself.
  const CURSOR_KEYS = ['tenants', 'products', 'variations', 'staff', 'sales', 'sale_items'];
  function getCursors() {
    let c = {}; try { c = JSON.parse(DB.getSetting('sync_cursors') || '{}'); } catch (e) {}
    // Migrate the old single cursor to the catalogue tables.
    const legacy = Number(DB.getSetting('sync_cursor') || 0);
    CURSOR_KEYS.forEach((k) => { if (c[k] == null) c[k] = (k === 'sales' || k === 'sale_items') ? 0 : legacy; });
    return c;
  }
  function maxSeq(rows, start) {
    return (rows || []).reduce((m, r) => Math.max(m, Number(r.seq) || 0), start || 0);
  }

  async function pull() {
    const cur = getCursors();
    // `since` keeps the old single-cursor backend working; the *_since params
    // drive the new per-table backend. Whichever the server understands, the
    // client advances cursors from the seq values on the rows it gets back.
    const since = Math.max(cur.tenants, cur.products, cur.variations, cur.staff);
    const qs = new URLSearchParams({
      since: String(since),
      tenants_since: cur.tenants, products_since: cur.products, variations_since: cur.variations,
      staff_since: cur.staff, sales_since: cur.sales, sale_items_since: cur.sale_items
    });
    const out = await apiFetch('/api/pull?' + qs.toString(), { method: 'GET' });
    (out.tenants || []).forEach(upsertTenant);
    (out.products || []).forEach(upsertProduct);
    (out.variations || []).forEach(upsertVariation);
    (out.staff || []).forEach(upsertStaff);
    (out.sales || []).forEach(upsertSale);
    (out.sale_items || []).forEach(upsertSaleItem);

    const next = {
      tenants: maxSeq(out.tenants, cur.tenants),
      products: maxSeq(out.products, cur.products),
      variations: maxSeq(out.variations, cur.variations),
      staff: maxSeq(out.staff, cur.staff),
      sales: maxSeq(out.sales, cur.sales),
      sale_items: maxSeq(out.sale_items, cur.sale_items)
    };
    DB.setSetting('sync_cursors', JSON.stringify(next));
    return { pulled: CURSOR_KEYS.reduce((n, k) => n + ((out[k] || []).length), 0) };
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
    DB.run(`INSERT INTO tenants(id,name,slug,tin,phone,email,address,currency,vat_rate,vat_inclusive,
        vat_enabled,vat_show_receipt,service_charge_enabled,service_charge_rate,service_charge_show_receipt,
        logo_on_receipt,order_no_on_receipt,analytics_enabled,categories,receipt_footer,logo,status,updated_at,created_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
      ON CONFLICT(id) DO UPDATE SET name=excluded.name,slug=excluded.slug,tin=excluded.tin,phone=excluded.phone,
        email=excluded.email,address=excluded.address,currency=excluded.currency,vat_rate=excluded.vat_rate,
        vat_inclusive=excluded.vat_inclusive,vat_enabled=excluded.vat_enabled,vat_show_receipt=excluded.vat_show_receipt,
        service_charge_enabled=excluded.service_charge_enabled,service_charge_rate=excluded.service_charge_rate,
        service_charge_show_receipt=excluded.service_charge_show_receipt,
        logo_on_receipt=excluded.logo_on_receipt,order_no_on_receipt=excluded.order_no_on_receipt,
        analytics_enabled=excluded.analytics_enabled,categories=excluded.categories,
        receipt_footer=excluded.receipt_footer,logo=excluded.logo,
        status=excluded.status,updated_at=excluded.updated_at`,
      [t.id, t.name, t.slug, t.tin, t.phone, t.email, t.address, t.currency || 'GYD',
       t.vat_rate ?? 15, t.vat_inclusive ?? 1, t.vat_enabled ?? 1, t.vat_show_receipt ?? 1,
       t.service_charge_enabled ?? 0, t.service_charge_rate ?? 0, t.service_charge_show_receipt ?? 1,
       t.logo_on_receipt ?? 1, t.order_no_on_receipt ?? 1, t.analytics_enabled ?? 0,
       t.categories ?? null, t.receipt_footer, t.logo, t.status || 'active',
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
    DB.run(`INSERT INTO variations(id,product_id,tenant_id,name,sku,barcode,price,cost,stock,track_stock,low_stock_threshold,supplier_id,discount_type,discount_value,active,updated_at,created_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
      ON CONFLICT(id) DO UPDATE SET name=excluded.name,sku=excluded.sku,barcode=excluded.barcode,price=excluded.price,
        cost=excluded.cost,stock=excluded.stock,track_stock=excluded.track_stock,low_stock_threshold=excluded.low_stock_threshold,
        supplier_id=excluded.supplier_id,discount_type=excluded.discount_type,discount_value=excluded.discount_value,
        active=excluded.active,updated_at=excluded.updated_at`,
      [v.id, v.product_id, v.tenant_id, v.name, v.sku, v.barcode, v.price, v.cost, v.stock,
       v.track_stock ?? 1, v.low_stock_threshold ?? 5, v.supplier_id, v.discount_type || 'none', v.discount_value ?? 0,
       v.active ?? 1, v.updated_at || DB.nowISO(), v.created_at || DB.nowISO()]);
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
  // Sales replicate to every device (overwrite by id; the cloud copy wins, which
  // also propagates voids). Marked synced since they came from the cloud.
  function upsertSale(s) {
    DB.run(`INSERT INTO sales(id,tenant_id,receipt_no,order_no,order_date,subtotal,vat_amount,total,
        cash_received,change_due,item_count,cashier,vat_inclusive,vat_rate,service_charge,service_charge_rate,
        currency,status,synced,created_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?)
      ON CONFLICT(id) DO UPDATE SET receipt_no=excluded.receipt_no,order_no=excluded.order_no,order_date=excluded.order_date,
        subtotal=excluded.subtotal,vat_amount=excluded.vat_amount,total=excluded.total,cash_received=excluded.cash_received,
        change_due=excluded.change_due,item_count=excluded.item_count,cashier=excluded.cashier,
        vat_inclusive=excluded.vat_inclusive,vat_rate=excluded.vat_rate,service_charge=excluded.service_charge,
        service_charge_rate=excluded.service_charge_rate,currency=excluded.currency,status=excluded.status,synced=1`,
      [s.id, s.tenant_id, s.receipt_no, s.order_no, s.order_date, s.subtotal, s.vat_amount, s.total,
       s.cash_received, s.change_due, s.item_count, s.cashier, s.vat_inclusive, s.vat_rate,
       s.service_charge ?? 0, s.service_charge_rate ?? 0, s.currency, s.status || 'completed',
       s.created_at || DB.nowISO()]);
  }
  function upsertSaleItem(it) {
    DB.run(`INSERT INTO sale_items(id,sale_id,tenant_id,product_id,variation_id,name,sku,qty,unit_price,line_total)
      VALUES(?,?,?,?,?,?,?,?,?,?)
      ON CONFLICT(id) DO UPDATE SET sale_id=excluded.sale_id,name=excluded.name,sku=excluded.sku,
        qty=excluded.qty,unit_price=excluded.unit_price,line_total=excluded.line_total`,
      [it.id, it.sale_id, it.tenant_id, it.product_id, it.variation_id, it.name, it.sku,
       it.qty, it.unit_price, it.line_total]);
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
      emit({ state: 'error', pending: pendingCount(), error: e && e.message });
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

  // Ping the sync API (optionally a not-yet-saved base) and report what it says.
  async function test(baseOverride) {
    const base = (baseOverride != null ? baseOverride : Config.apiBase() || '').replace(/\/+$/, '');
    if (!base) throw new Error('No API base URL set');
    const res = await fetch(base + '/api/pull?since=0', { headers: { 'Content-Type': 'application/json' } });
    if (!res.ok) throw new Error('HTTP ' + res.status + ' from server');
    let j;
    try { j = await res.json(); } catch (e) { throw new Error('Server did not return JSON (wrong URL?)'); }
    if (!('cursor' in j)) throw new Error('Unexpected response (is this the sync API?)');
    return { ok: true, tenants: (j.tenants || []).length, cursor: j.cursor };
  }

  return { start, run, test, queue, pendingCount, onChange, configured, isOnline };
})();
