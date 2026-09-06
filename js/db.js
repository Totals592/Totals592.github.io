/*
 * Totals POS - Local database layer
 * ---------------------------------------------------------------------------
 * A real SQLite database compiled to WebAssembly (sql.js) runs entirely in the
 * browser. The binary image is persisted to IndexedDB so all data survives
 * reloads, offline restarts and app updates. This is the offline system of
 * record; the cloud backend is a mirror kept up to date by js/sync.js.
 */
window.DB = (function () {
  'use strict';

  const IDB_NAME = 'totals-pos';
  const IDB_STORE = 'sqlite';
  const IDB_KEY = 'db.sqlite';

  let SQL = null;      // sql.js module
  let db = null;       // Database instance
  let persistTimer = null;
  let ready = null;    // Promise resolved when DB is usable

  /* ---------- IndexedDB blob storage (holds the raw SQLite file) ---------- */
  function idb() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(IDB_NAME, 1);
      req.onupgradeneeded = () => {
        const d = req.result;
        if (!d.objectStoreNames.contains(IDB_STORE)) d.createObjectStore(IDB_STORE);
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }
  async function idbGet(key) {
    const d = await idb();
    return new Promise((resolve, reject) => {
      const tx = d.transaction(IDB_STORE, 'readonly').objectStore(IDB_STORE).get(key);
      tx.onsuccess = () => resolve(tx.result || null);
      tx.onerror = () => reject(tx.error);
    });
  }
  async function idbPut(key, val) {
    const d = await idb();
    return new Promise((resolve, reject) => {
      const tx = d.transaction(IDB_STORE, 'readwrite').objectStore(IDB_STORE).put(val, key);
      tx.onsuccess = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }

  /* ---------- Persistence ---------- */
  function persistNow() {
    if (!db) return;
    const data = db.export(); // Uint8Array
    return idbPut(IDB_KEY, data);
  }
  function schedulePersist() {
    clearTimeout(persistTimer);
    persistTimer = setTimeout(persistNow, 300);
  }

  /* ---------- Schema ---------- */
  const SCHEMA = `
  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
  );

  CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT,
    tin TEXT,
    phone TEXT,
    email TEXT,
    address TEXT,
    currency TEXT DEFAULT 'GYD',
    vat_rate REAL DEFAULT 15,
    vat_inclusive INTEGER DEFAULT 1,
    vat_enabled INTEGER DEFAULT 1,
    vat_show_receipt INTEGER DEFAULT 1,
    service_charge_enabled INTEGER DEFAULT 0,
    service_charge_rate REAL DEFAULT 0,
    service_charge_show_receipt INTEGER DEFAULT 1,
    logo_on_receipt INTEGER DEFAULT 1,
    categories TEXT,
    receipt_footer TEXT,
    logo TEXT,
    status TEXT DEFAULT 'active',
    updated_at TEXT,
    created_at TEXT
  );

  CREATE TABLE IF NOT EXISTS suppliers (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    contact TEXT,
    phone TEXT,
    email TEXT,
    address TEXT,
    updated_at TEXT,
    created_at TEXT
  );

  CREATE TABLE IF NOT EXISTS products (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    category TEXT DEFAULT 'General',
    image TEXT,
    color TEXT,
    active INTEGER DEFAULT 1,
    sort INTEGER DEFAULT 0,
    updated_at TEXT,
    created_at TEXT
  );

  /* Each variation is a distinct sellable unit with its own SKU + stock. */
  CREATE TABLE IF NOT EXISTS variations (
    id TEXT PRIMARY KEY,
    product_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    name TEXT DEFAULT 'Default',
    sku TEXT,
    barcode TEXT,
    price REAL NOT NULL DEFAULT 0,
    cost REAL DEFAULT 0,
    stock REAL DEFAULT 0,
    track_stock INTEGER DEFAULT 1,
    low_stock_threshold REAL DEFAULT 5,
    supplier_id TEXT,
    active INTEGER DEFAULT 1,
    updated_at TEXT,
    created_at TEXT
  );

  CREATE TABLE IF NOT EXISTS sales (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    receipt_no TEXT,
    order_no INTEGER,
    order_date TEXT,
    subtotal REAL,
    vat_amount REAL,
    total REAL,
    cash_received REAL,
    change_due REAL,
    item_count REAL,
    cashier TEXT,
    vat_inclusive INTEGER,
    vat_rate REAL,
    service_charge REAL DEFAULT 0,
    service_charge_rate REAL DEFAULT 0,
    currency TEXT,
    status TEXT DEFAULT 'completed',
    synced INTEGER DEFAULT 0,
    created_at TEXT
  );

  CREATE TABLE IF NOT EXISTS sale_items (
    id TEXT PRIMARY KEY,
    sale_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    product_id TEXT,
    variation_id TEXT,
    name TEXT,
    sku TEXT,
    qty REAL,
    unit_price REAL,
    line_total REAL
  );

  /* Per-tenant staff accounts used for the till login. */
  CREATE TABLE IF NOT EXISTS staff (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    username TEXT NOT NULL,
    pin_hash TEXT,
    salt TEXT,
    role TEXT DEFAULT 'cashier',
    active INTEGER DEFAULT 1,
    updated_at TEXT,
    created_at TEXT
  );

  /* Durable outbox: every change that must reach the cloud lands here. */
  CREATE TABLE IF NOT EXISTS sync_queue (
    id TEXT PRIMARY KEY,
    tenant_id TEXT,
    entity TEXT,
    entity_id TEXT,
    op TEXT,
    payload TEXT,
    attempts INTEGER DEFAULT 0,
    last_error TEXT,
    created_at TEXT
  );

  CREATE INDEX IF NOT EXISTS idx_prod_tenant ON products(tenant_id);
  CREATE INDEX IF NOT EXISTS idx_var_product ON variations(product_id);
  CREATE INDEX IF NOT EXISTS idx_var_tenant ON variations(tenant_id);
  CREATE INDEX IF NOT EXISTS idx_sales_tenant ON sales(tenant_id);
  CREATE INDEX IF NOT EXISTS idx_items_sale ON sale_items(sale_id);
  CREATE INDEX IF NOT EXISTS idx_staff_tenant ON staff(tenant_id);
  `;

  /* ---------- Query helpers ---------- */
  function rowsFromResult(res) {
    if (!res || !res.length) return [];
    const { columns, values } = res[0];
    return values.map((row) => {
      const o = {};
      columns.forEach((c, i) => (o[c] = row[i]));
      return o;
    });
  }
  function all(sql, params = []) { return rowsFromResult(db.exec(sql, params)); }
  function get(sql, params = []) { const r = all(sql, params); return r[0] || null; }
  function run(sql, params = []) { db.run(sql, params); schedulePersist(); }

  function uid(prefix) {
    const base = (crypto.randomUUID ? crypto.randomUUID() : (Date.now().toString(36) + Math.random().toString(36).slice(2)));
    return (prefix ? prefix + '_' : '') + base;
  }
  function nowISO() { return new Date().toISOString(); }

  /* ---------- Settings ---------- */
  function getSetting(key, fallback = null) {
    const r = get('SELECT value FROM settings WHERE key = ?', [key]);
    return r ? r.value : fallback;
  }
  function setSetting(key, value) {
    run('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
      [key, String(value)]);
  }

  /* ---------- Seed a demo tenant so the app is usable on first run ---------- */
  function seedIfEmpty() {
    const count = get('SELECT COUNT(*) AS n FROM tenants');
    if (count && count.n > 0) return;

    const tid = uid('ten');
    const ts = nowISO();
    run(`INSERT INTO tenants(id,name,slug,tin,phone,email,address,currency,vat_rate,vat_inclusive,receipt_footer,status,updated_at,created_at)
         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [tid, 'Corner Store Demo', 'corner-store', 'C0001234567', '+233 20 000 0000',
       'shop@example.com', '12 Market Street, Accra', 'GYD', 15, 1,
       'Thank you for your purchase! Goods sold are not returnable.', 'active', ts, ts]);

    setSetting('active_tenant_id', tid);

    const sup = uid('sup');
    run(`INSERT INTO suppliers(id,tenant_id,name,contact,phone,email,updated_at,created_at)
         VALUES(?,?,?,?,?,?,?,?)`,
      [sup, tid, 'Local Wholesale Ltd', 'Ama Owusu', '+233 24 111 2222', 'sales@wholesale.example', ts, ts]);

    const demo = [
      ['Espresso',        'Drinks',  '#7c3aed', [['Single', 12.00, 3.0, 120], ['Double', 18.00, 4.5, 80]]],
      ['Cappuccino',      'Drinks',  '#0ea5e9', [['Regular', 22.00, 6.0, 60]]],
      ['Bottled Water',   'Drinks',  '#14b8a6', [['500ml', 5.00, 2.0, 200], ['1.5L', 9.00, 4.0, 40]]],
      ['Meat Pie',        'Food',    '#f59e0b', [['Each', 15.00, 7.0, 24]]],
      ['Club Sandwich',   'Food',    '#ef4444', [['Each', 35.00, 15.0, 10]]],
      ['Jollof Rice',     'Food',    '#f97316', [['Plate', 40.00, 18.0, 30]]],
      ['Haircut',         'Services','#22c55e', [['Standard', 50.00, 0, 0]]],
      ['Phone Airtime',   'Services','#3b82f6', [['GHS 10', 10.00, 9.5, 999]]]
    ];
    let sort = 0;
    demo.forEach(([name, cat, color, variants]) => {
      const pid = uid('prd');
      run(`INSERT INTO products(id,tenant_id,name,category,color,active,sort,updated_at,created_at)
           VALUES(?,?,?,?,?,?,?,?,?)`, [pid, tid, name, cat, color, 1, sort++, ts, ts]);
      variants.forEach(([vname, price, cost, stock]) => {
        run(`INSERT INTO variations(id,product_id,tenant_id,name,sku,price,cost,stock,track_stock,low_stock_threshold,supplier_id,active,updated_at,created_at)
             VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
          [uid('var'), pid, tid, vname, 'SKU-' + Math.random().toString(36).slice(2, 8).toUpperCase(),
           price, cost, stock, name === 'Haircut' ? 0 : 1, 5, sup, 1, ts, ts]);
      });
    });
    persistNow();
  }

  /* Ensure every tenant has at least a manager + cashier so someone can log
     in. Default credentials are shown on the login screen for the demo. */
  async function ensureStaff() {
    const tenants = all('SELECT id FROM tenants');
    for (const t of tenants) {
      const has = get('SELECT COUNT(*) AS n FROM staff WHERE tenant_id = ? AND active = 1', [t.id]);
      if (has && has.n > 0) continue;
      const defaults = [
        { name: 'Manager', username: 'manager', pin: '1234', role: 'manager' },
        { name: 'Cashier', username: 'cashier', pin: '4321', role: 'cashier' }
      ];
      for (const d of defaults) {
        const salt = Config.randomSalt();
        const hash = await Config.hashPin(d.pin, salt);
        const ts = nowISO();
        run(`INSERT INTO staff(id,tenant_id,name,username,pin_hash,salt,role,active,updated_at,created_at)
             VALUES(?,?,?,?,?,?,?,1,?,?)`,
          [uid('stf'), t.id, d.name, d.username, hash, salt, d.role, ts, ts]);
      }
    }
    persistNow();
  }

  /* Add columns introduced after the first release, for existing databases. */
  function ensureColumn(table, col, decl) {
    const cols = all(`PRAGMA table_info(${table})`);
    if (!cols.find((c) => c.name === col)) run(`ALTER TABLE ${table} ADD COLUMN ${col} ${decl}`);
  }
  function migrate() {
    ensureColumn('tenants', 'vat_enabled', 'INTEGER DEFAULT 1');
    ensureColumn('tenants', 'vat_show_receipt', 'INTEGER DEFAULT 1');
    ensureColumn('tenants', 'service_charge_enabled', 'INTEGER DEFAULT 0');
    ensureColumn('tenants', 'service_charge_rate', 'REAL DEFAULT 0');
    ensureColumn('tenants', 'service_charge_show_receipt', 'INTEGER DEFAULT 1');
    ensureColumn('sales', 'service_charge', 'REAL DEFAULT 0');
    ensureColumn('sales', 'service_charge_rate', 'REAL DEFAULT 0');
    ensureColumn('sales', 'order_no', 'INTEGER');
    ensureColumn('sales', 'order_date', 'TEXT');
    ensureColumn('tenants', 'logo_on_receipt', 'INTEGER DEFAULT 1');
    ensureColumn('tenants', 'categories', 'TEXT');
  }

  /* ---------- Init ---------- */
  async function init() {
    if (ready) return ready;
    ready = (async () => {
      SQL = await initSqlJs({ locateFile: () => './vendor/sql-wasm.wasm' });
      const saved = await idbGet(IDB_KEY);
      db = saved ? new SQL.Database(new Uint8Array(saved)) : new SQL.Database();
      db.run('PRAGMA foreign_keys = ON;');
      db.run(SCHEMA);
      migrate();
      seedIfEmpty();
      // Make sure an active tenant is always set.
      if (!getSetting('active_tenant_id')) {
        const t = get('SELECT id FROM tenants ORDER BY created_at LIMIT 1');
        if (t) setSetting('active_tenant_id', t.id);
      }
      await ensureStaff();
      return true;
    })();
    return ready;
  }

  return {
    init, all, get, run, uid, nowISO,
    getSetting, setSetting, persistNow,
    // expose for import/export/backup
    export: () => db.export(),
    import: async (bytes) => { db = new SQL.Database(new Uint8Array(bytes)); db.run(SCHEMA); await persistNow(); },
    wipe: async () => { await idbPut(IDB_KEY, null); location.reload(); }
  };
})();
