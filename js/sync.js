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

  // `a ?? b` without the operator — Safari 12 (iOS 12 iPads) can't parse `??`.
  function nz(v, d) { return v === null || v === undefined ? d : v; }

  function onChange(fn) { listeners.push(fn); }
  function emit(state) { listeners.forEach((f) => { try { f(state); } catch (e) {} }); }

  function isOnline() { return navigator.onLine; }
  function configured() { return !!Config.apiBase(); }

  /* ---------- Who is this device to the cloud? ----------
   * The owner's device holds the admin key and syncs every shop. Any other
   * device holds a token for ONE shop, issued when a staff member of that shop
   * signs in online — the cloud only ever sends it that shop's data. */
  function tokenFor(tid) { return tid ? DB.getSetting('sync_token_' + tid) : null; }
  function hasToken(tid) { return !!tokenFor(tid); }
  function authHeaders() {
    const key = DB.getSetting('admin_key');
    if (key) return { 'X-Admin-Key': key };
    const tok = tokenFor(Config.activeTenantId());
    return tok ? { 'X-Device-Token': tok } : null;
  }
  // Cursor/outbox scope: 'admin' (all shops) or the active shop's id.
  function scope() {
    if (DB.getSetting('admin_key')) return 'admin';
    const tid = Config.activeTenantId();
    return tokenFor(tid) ? tid : null;
  }

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

  // Uploads this device can actually send (a shop device only sends its own
  // shop's changes).
  function pendingCount() {
    const sc = scope();
    const r = sc && sc !== 'admin'
      ? DB.get('SELECT COUNT(*) AS n FROM sync_queue WHERE tenant_id = ?', [sc])
      : DB.get('SELECT COUNT(*) AS n FROM sync_queue');
    return r ? r.n : 0;
  }

  // `auth: false` for the public endpoints (sign-in, sign-up).
  async function apiFetch(path, opts, auth) {
    const base = Config.apiBase();
    const headers = Object.assign({ 'Content-Type': 'application/json' }, auth === false ? {} : (authHeaders() || {}));
    const res = await fetch(base + path, Object.assign({}, opts, { headers }));
    let body = null;
    try { body = await res.json(); } catch (e) {}
    if (!res.ok) {
      const err = new Error((body && body.message) || ('HTTP ' + res.status));
      err.status = res.status; err.code = body && body.error;
      // The cloud no longer accepts this shop token (staff removed, shop
      // deleted, or keys rotated): forget it so the next sign-in renews it.
      if (res.status === 401 && auth !== false && !DB.getSetting('admin_key')) {
        DB.setSetting('sync_token_' + Config.activeTenantId(), '');
      }
      throw err;
    }
    return body;
  }

  /* ---------- PUSH: upload the outbox ---------- */
  async function push() {
    // A shop device only uploads its own shop's changes; anything queued for
    // another shop waits until someone from that shop signs in here.
    const sc = scope();
    const rows = sc === 'admin'
      ? DB.all('SELECT * FROM sync_queue ORDER BY created_at LIMIT 100')
      : DB.all('SELECT * FROM sync_queue WHERE tenant_id = ? ORDER BY created_at LIMIT 100', [sc]);
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
    const rejected = new Set(out.rejected || []);
    rows.forEach((r) => {
      if (rejected.has(r.id)) {
        // Refused by the cloud for this device (e.g. another shop's data) —
        // retrying can never succeed, so drop it.
        DB.run('DELETE FROM sync_queue WHERE id = ?', [r.id]);
      } else if (applied.has(r.id)) {
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
  const CURSOR_KEYS = ['tenants', 'products', 'variations', 'staff', 'sales', 'sale_items',
    'subscriptions', 'subscription_audit_log', 'devices'];
  // Cursors are kept per scope (admin / each shop), since each scope sees a
  // different slice of the cloud. A new scope starts from 0 = full download.
  function cursorKey() { return 'sync_cursors:' + scope(); }
  function getCursors() {
    let c = {}; try { c = JSON.parse(DB.getSetting(cursorKey()) || '{}'); } catch (e) {}
    CURSOR_KEYS.forEach((k) => { if (c[k] == null) c[k] = 0; });
    return c;
  }
  function maxSeq(rows, start) {
    return (rows || []).reduce((m, r) => Math.max(m, Number(r.seq) || 0), start || 0);
  }

  async function pull(deep) {
    const cur = getCursors();
    // Tenants and staff are tiny and login-critical, so ALWAYS fetch them in
    // full (from seq 0). This guarantees a newly created shop or staff account
    // shows up on every other device, even if a table cursor got ahead or the
    // backend collapses the per-table cursors to a single one. The larger
    // catalogue/sales tables stay incremental. A `deep` pull fetches everything
    // from 0 (used as a login safety net when a shop can't be found).
    const c = {
      tenants: 0,
      staff: 0,
      products: deep ? 0 : cur.products,
      variations: deep ? 0 : cur.variations,
      sales: deep ? 0 : cur.sales,
      sale_items: deep ? 0 : cur.sale_items,
      // Subscriptions/audit log/devices are small, admin-facing tables —
      // always fetched in full, same reasoning as tenants/staff.
      subscriptions: 0, subscription_audit_log: 0, devices: 0
    };
    // `since` keeps an old single-cursor backend working; the *_since params
    // drive the per-table backend. For a deep pull we ask for everything.
    const since = deep ? 0 : Math.max(cur.products, cur.variations, cur.sales, cur.sale_items);
    const qs = new URLSearchParams({
      since: String(since),
      tenants_since: c.tenants, products_since: c.products, variations_since: c.variations,
      staff_since: c.staff, sales_since: c.sales, sale_items_since: c.sale_items,
      subscriptions_since: c.subscriptions, subscription_audit_log_since: c.subscription_audit_log,
      devices_since: c.devices
    });
    const out = await apiFetch('/api/pull?' + qs.toString(), { method: 'GET' });
    (out.tenants || []).forEach(upsertTenant);
    (out.products || []).forEach(upsertProduct);
    (out.variations || []).forEach(upsertVariation);
    (out.staff || []).forEach(upsertStaff);
    (out.sales || []).forEach(upsertSale);
    (out.sale_items || []).forEach(upsertSaleItem);
    (out.subscriptions || []).forEach(upsertSubscription);
    (out.subscription_audit_log || []).forEach(upsertAuditLogEntry);
    (out.devices || []).forEach(upsertDevice);

    // Advance each cursor to the highest seq we've seen (never move it backward).
    const next = {
      tenants: Math.max(cur.tenants, maxSeq(out.tenants, cur.tenants)),
      products: Math.max(cur.products, maxSeq(out.products, cur.products)),
      variations: Math.max(cur.variations, maxSeq(out.variations, cur.variations)),
      staff: Math.max(cur.staff, maxSeq(out.staff, cur.staff)),
      subscriptions: Math.max(cur.subscriptions, maxSeq(out.subscriptions, cur.subscriptions)),
      subscription_audit_log: Math.max(cur.subscription_audit_log, maxSeq(out.subscription_audit_log, cur.subscription_audit_log)),
      devices: Math.max(cur.devices, maxSeq(out.devices, cur.devices)),
      sales: Math.max(cur.sales, maxSeq(out.sales, cur.sales)),
      sale_items: Math.max(cur.sale_items, maxSeq(out.sale_items, cur.sale_items))
    };
    DB.setSetting(cursorKey(), JSON.stringify(next));
    return { pulled: CURSOR_KEYS.reduce((n, k) => n + ((out[k] || []).length), 0) };
  }

  // Full refresh: pull every table from scratch. Used when a shop can't be
  // found on login, so a device that missed something still catches up.
  async function pullAll() {
    if (!configured() || !isOnline() || !authHeaders()) return;
    try {
      await pull(true);
      DB.setSetting('last_sync_at', DB.nowISO());
      DB.persistNow();
      emit({ state: 'synced', pending: pendingCount(), at: DB.getSetting('last_sync_at') });
    } catch (e) {
      emit({ state: 'error', pending: pendingCount(), error: e && e.message });
    }
  }

  // Upserts apply "last write wins" using updated_at so remote edits win only
  // when they are newer than the local copy.
  function newer(remote, table, pkCol) {
    pkCol = pkCol || 'id';
    const local = DB.get(`SELECT updated_at FROM ${table} WHERE ${pkCol} = ?`, [remote[pkCol]]);
    if (!local) return true;
    return String(remote.updated_at || '') > String(local.updated_at || '');
  }
  function upsertTenant(t) {
    if (!newer(t, 'tenants')) return;
    DB.run(`INSERT INTO tenants(id,name,slug,tin,phone,email,address,currency,vat_rate,vat_inclusive,
        vat_enabled,vat_show_receipt,service_charge_enabled,service_charge_rate,service_charge_show_receipt,
        logo_on_receipt,order_no_on_receipt,analytics_enabled,remote_sales_enabled,import_inventory_enabled,expiry_tracking_enabled,categories,receipt_footer,logo,status,updated_at,created_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
      ON CONFLICT(id) DO UPDATE SET name=excluded.name,slug=excluded.slug,tin=excluded.tin,phone=excluded.phone,
        email=excluded.email,address=excluded.address,currency=excluded.currency,vat_rate=excluded.vat_rate,
        vat_inclusive=excluded.vat_inclusive,vat_enabled=excluded.vat_enabled,vat_show_receipt=excluded.vat_show_receipt,
        service_charge_enabled=excluded.service_charge_enabled,service_charge_rate=excluded.service_charge_rate,
        service_charge_show_receipt=excluded.service_charge_show_receipt,
        logo_on_receipt=excluded.logo_on_receipt,order_no_on_receipt=excluded.order_no_on_receipt,
        analytics_enabled=excluded.analytics_enabled,remote_sales_enabled=excluded.remote_sales_enabled,
        import_inventory_enabled=excluded.import_inventory_enabled,
        expiry_tracking_enabled=excluded.expiry_tracking_enabled,
        categories=excluded.categories,receipt_footer=excluded.receipt_footer,logo=excluded.logo,
        status=excluded.status,updated_at=excluded.updated_at`,
      [t.id, t.name, t.slug, t.tin, t.phone, t.email, t.address, t.currency || 'GYD',
       nz(t.vat_rate, 15), nz(t.vat_inclusive, 1), nz(t.vat_enabled, 1), nz(t.vat_show_receipt, 1),
       nz(t.service_charge_enabled, 0), nz(t.service_charge_rate, 0), nz(t.service_charge_show_receipt, 1),
       nz(t.logo_on_receipt, 1), nz(t.order_no_on_receipt, 1), nz(t.analytics_enabled, 0), nz(t.remote_sales_enabled, 1),
       nz(t.import_inventory_enabled, 0), nz(t.expiry_tracking_enabled, 0),
       nz(t.categories, null), t.receipt_footer, t.logo, t.status || 'active',
       t.updated_at || DB.nowISO(), t.created_at || DB.nowISO()]);
    // A shop deleted on another device: purge its data here too (keep the
    // tombstone row so it stays hidden and is never resurrected as active).
    if (t.status === 'deleted') {
      ['sale_items', 'sales', 'variations', 'products', 'suppliers', 'staff'].forEach((tbl) => {
        DB.run('DELETE FROM ' + tbl + ' WHERE tenant_id = ?', [t.id]);
      });
    }
  }
  function upsertProduct(p) {
    if (!newer(p, 'products')) return;
    DB.run(`INSERT INTO products(id,tenant_id,name,description,category,image,color,active,sort,updated_at,created_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?)
      ON CONFLICT(id) DO UPDATE SET name=excluded.name,description=excluded.description,category=excluded.category,
        image=excluded.image,color=excluded.color,active=excluded.active,sort=excluded.sort,updated_at=excluded.updated_at`,
      [p.id, p.tenant_id, p.name, p.description, p.category || 'General', p.image, p.color,
       nz(p.active, 1), nz(p.sort, 0), p.updated_at || DB.nowISO(), p.created_at || DB.nowISO()]);
  }
  function upsertVariation(v) {
    if (!newer(v, 'variations')) return;
    DB.run(`INSERT INTO variations(id,product_id,tenant_id,name,sku,barcode,price,cost,stock,track_stock,low_stock_threshold,supplier_id,discount_type,discount_value,expiry_date,active,updated_at,created_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
      ON CONFLICT(id) DO UPDATE SET name=excluded.name,sku=excluded.sku,barcode=excluded.barcode,price=excluded.price,
        cost=excluded.cost,stock=excluded.stock,track_stock=excluded.track_stock,low_stock_threshold=excluded.low_stock_threshold,
        supplier_id=excluded.supplier_id,discount_type=excluded.discount_type,discount_value=excluded.discount_value,
        expiry_date=excluded.expiry_date,active=excluded.active,updated_at=excluded.updated_at`,
      [v.id, v.product_id, v.tenant_id, v.name, v.sku, v.barcode, v.price, v.cost, v.stock,
       nz(v.track_stock, 1), nz(v.low_stock_threshold, 5), v.supplier_id, v.discount_type || 'none', nz(v.discount_value, 0),
       nz(v.expiry_date, null), nz(v.active, 1), v.updated_at || DB.nowISO(), v.created_at || DB.nowISO()]);
  }
  function upsertStaff(s) {
    if (!newer(s, 'staff')) return;
    DB.run(`INSERT INTO staff(id,tenant_id,name,username,pin_hash,salt,role,can_view_sales,can_manage_inventory,active,updated_at,created_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
      ON CONFLICT(id) DO UPDATE SET name=excluded.name,username=excluded.username,pin_hash=excluded.pin_hash,
        salt=excluded.salt,role=excluded.role,can_view_sales=excluded.can_view_sales,
        can_manage_inventory=excluded.can_manage_inventory,active=excluded.active,updated_at=excluded.updated_at`,
      [s.id, s.tenant_id, s.name, (s.username || '').toLowerCase(), s.pin_hash, s.salt,
       s.role || 'cashier', nz(s.can_view_sales, 0), nz(s.can_manage_inventory, 0),
       nz(s.active, 1), s.updated_at || DB.nowISO(), s.created_at || DB.nowISO()]);
  }
  // Sales replicate to every device (overwrite by id; the cloud copy wins, which
  // also propagates voids). Marked synced since they came from the cloud.
  function upsertSale(s) {
    DB.run(`INSERT INTO sales(id,tenant_id,receipt_no,order_no,order_date,subtotal,vat_amount,total,
        cash_received,change_due,item_count,cashier,vat_inclusive,vat_rate,service_charge,service_charge_rate,
        origin_device,currency,status,synced,created_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?)
      ON CONFLICT(id) DO UPDATE SET receipt_no=excluded.receipt_no,order_no=excluded.order_no,order_date=excluded.order_date,
        subtotal=excluded.subtotal,vat_amount=excluded.vat_amount,total=excluded.total,cash_received=excluded.cash_received,
        change_due=excluded.change_due,item_count=excluded.item_count,cashier=excluded.cashier,
        vat_inclusive=excluded.vat_inclusive,vat_rate=excluded.vat_rate,service_charge=excluded.service_charge,
        service_charge_rate=excluded.service_charge_rate,origin_device=excluded.origin_device,
        currency=excluded.currency,status=excluded.status,synced=1`,
      [s.id, s.tenant_id, s.receipt_no, s.order_no, s.order_date, s.subtotal, s.vat_amount, s.total,
       s.cash_received, s.change_due, s.item_count, s.cashier, s.vat_inclusive, s.vat_rate,
       nz(s.service_charge, 0), nz(s.service_charge_rate, 0), nz(s.origin_device, null), s.currency, s.status || 'completed',
       s.created_at || DB.nowISO()]);
  }
  function upsertSaleItem(it) {
    DB.run(`INSERT INTO sale_items(id,sale_id,tenant_id,product_id,variation_id,name,sku,qty,unit_price,list_price,line_total)
      VALUES(?,?,?,?,?,?,?,?,?,?,?)
      ON CONFLICT(id) DO UPDATE SET sale_id=excluded.sale_id,name=excluded.name,sku=excluded.sku,
        qty=excluded.qty,unit_price=excluded.unit_price,list_price=excluded.list_price,line_total=excluded.line_total`,
      [it.id, it.sale_id, it.tenant_id, it.product_id, it.variation_id, it.name, it.sku,
       it.qty, it.unit_price, nz(it.list_price, it.unit_price), it.line_total]);
  }
  // Subscriptions: server is authoritative (set only via the Admin's
  // Subscription modal + the cloud's license endpoint) — plain last-write-wins.
  function upsertSubscription(s) {
    if (!newer(s, 'subscriptions', 'tenant_id')) return;
    DB.run(`INSERT INTO subscriptions(tenant_id,plan,status,started_at,expires_at,grace_until,entitlements,updated_at,created_at)
      VALUES(?,?,?,?,?,?,?,?,?)
      ON CONFLICT(tenant_id) DO UPDATE SET plan=excluded.plan,status=excluded.status,started_at=excluded.started_at,
        expires_at=excluded.expires_at,grace_until=excluded.grace_until,entitlements=excluded.entitlements,
        updated_at=excluded.updated_at`,
      [s.tenant_id, s.plan || 'trial', s.status || 'active', s.started_at, s.expires_at, s.grace_until,
       typeof s.entitlements === 'string' ? s.entitlements : JSON.stringify(s.entitlements || {}),
       s.updated_at || DB.nowISO(), s.created_at || DB.nowISO()]);
  }
  // Audit log entries are append-only — insert once, never modified.
  function upsertAuditLogEntry(a) {
    DB.run(`INSERT OR IGNORE INTO subscription_audit_log(id,tenant_id,action,from_plan,to_plan,from_expires,to_expires,note,at)
      VALUES(?,?,?,?,?,?,?,?,?)`,
      [a.id, a.tenant_id, a.action, a.from_plan, a.to_plan, a.from_expires, a.to_expires, a.note, a.at || DB.nowISO()]);
  }
  // Devices are recorded server-side (as a side effect of a license check-in)
  // and only ever pulled, never pushed from a register.
  function upsertDevice(d) {
    DB.run(`INSERT INTO devices(device_id,tenant_id,device_name,first_seen,last_seen)
      VALUES(?,?,?,?,?)
      ON CONFLICT(device_id) DO UPDATE SET device_name=excluded.device_name,last_seen=excluded.last_seen`,
      [d.device_id, d.tenant_id, d.device_name, d.first_seen || DB.nowISO(), d.last_seen || DB.nowISO()]);
  }

  /* ---------- License check-in ----------
   * Fetches a freshly SIGNED token for the active tenant and caches it. This
   * is the only network call the subscription system ever makes — every
   * other check (expiry warning, grace countdown, hard lock) runs entirely
   * off the cached, verified token, so a sale never needs it. Throttled so a
   * healthy device only calls it a few times a day, not on every sync tick.
   */
  const LICENSE_CHECK_INTERVAL_MS = 4 * 60 * 60 * 1000; // 4 hours
  async function refreshLicense(force) {
    if (!configured() || !isOnline() || !authHeaders()) return;
    const tid = Config.activeTenantId();
    if (!tid) return;
    const lastCheck = Number(DB.getSetting('license_checked_at_' + tid) || 0);
    if (!force && Date.now() - lastCheck < LICENSE_CHECK_INTERVAL_MS) return;
    try {
      const qs = new URLSearchParams({
        tenant_id: tid, device_id: Config.deviceId(), device_name: Config.deviceName()
      });
      const out = await apiFetch('/api/license?' + qs.toString(), { method: 'GET' });
      if (out && out.token) {
        DB.setSetting('license_token_' + tid, out.token);
        DB.setSetting('license_checked_at_' + tid, String(Date.now()));
        DB.persistNow();
      }
    } catch (e) { /* license check is best-effort — never blocks a sale */ }
    await Config.refreshLicenseState(tid);
  }

  /* ---------- Orchestration ---------- */
  let currentRun = null;
  async function run(force) {
    // A forced run (sign-in, "Sync now") waits for one already in flight and
    // then runs again, so its caller sees fresh data.
    if (running) { if (force && currentRun) { await currentRun; return run(force); } return; }
    currentRun = runOnce(force);
    return currentRun;
  }
  async function runOnce(force) {
    if (!configured()) { emit({ state: 'local-only', pending: pendingCount() }); return; }
    if (!isOnline() && !force) { emit({ state: 'offline', pending: pendingCount() }); return; }
    if (!authHeaders()) { emit({ state: 'signin', pending: pendingCount() }); return; }
    running = true;
    emit({ state: 'syncing', pending: pendingCount() });
    try {
      await pull();
      await push();
      await refreshLicense(force);
      DB.setSetting('last_sync_at', DB.nowISO());
      DB.persistNow();
      emit({ state: 'synced', pending: pendingCount(), at: DB.getSetting('last_sync_at') });
    } catch (e) {
      emit({ state: authHeaders() ? 'error' : 'signin', pending: pendingCount(), error: e && e.message });
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

  // Ping the sync API (optionally a not-yet-saved base) and report who the
  // cloud thinks this device is.
  async function test(baseOverride) {
    const base = (baseOverride != null ? baseOverride : Config.apiBase() || '').replace(/\/+$/, '');
    if (!base) throw new Error('No API base URL set');
    const res = await fetch(base + '/api/whoami', { headers: Object.assign({ 'Content-Type': 'application/json' }, authHeaders() || {}) });
    let j = null;
    try { j = await res.json(); } catch (e) { throw new Error('Server did not return JSON (wrong URL?)'); }
    if (res.status === 401) return { ok: true, scope: null, error: j && j.error };
    if (!res.ok) throw new Error('HTTP ' + res.status + ' from server');
    return { ok: true, scope: j.scope, tenant_id: j.tenant_id };
  }

  /* ---------- Sign-in / sign-up / admin calls ---------- */
  // Check a staff member's credentials with the cloud and keep the shop token.
  async function login(shop, username, pin) {
    const out = await apiFetch('/api/login', {
      method: 'POST',
      body: JSON.stringify({ shop, username, pin, device_id: Config.deviceId(), device_name: Config.deviceName() })
    }, false);
    DB.setSetting('sync_token_' + out.tenant_id, out.token);
    DB.persistNow();
    return out;
  }
  function signup(form) { return apiFetch('/api/signup', { method: 'POST', body: JSON.stringify(form) }, false); }
  function listSignups() { return apiFetch('/api/signups', { method: 'GET' }); }
  function approveSignup(id) { return apiFetch('/api/signups/approve', { method: 'POST', body: JSON.stringify({ id }) }); }
  function rejectSignup(id) { return apiFetch('/api/signups/reject', { method: 'POST', body: JSON.stringify({ id }) }); }
  async function shopNameAvailable(name) {
    const out = await apiFetch('/api/shop-name-available?' + new URLSearchParams({ name, tenant_id: Config.activeTenantId() || '' }), { method: 'GET' });
    return !!out.available;
  }
  function isAdminDevice() { return !!DB.getSetting('admin_key'); }

  return { start, run, pullAll, refreshLicense, test, queue, pendingCount, onChange, configured, isOnline,
    authHeaders, hasToken, login, signup, listSignups, approveSignup, rejectSignup, shopNameAvailable, isAdminDevice };
})();
