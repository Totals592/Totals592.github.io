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
// The owner's admin key: a device that presents it (X-Admin-Key) syncs every
// shop and can approve sign-ups. Every other device only ever sees its own
// shop, via a device token issued by /api/login. ADMIN_TOKEN is the old name.
const ADMIN_KEY = process.env.ADMIN_KEY || process.env.ADMIN_TOKEN || 'change-me-admin-token';
const ADMIN_TOKEN = ADMIN_KEY;
// Optional sign-up e-mail notification (https://resend.com).
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const NOTIFY_EMAIL = process.env.NOTIFY_EMAIL || '';
const NOTIFY_FROM = process.env.NOTIFY_FROM || 'TS - POS <onboarding@resend.dev>';
const RESEND_API_URL = process.env.RESEND_API_URL || 'https://api.resend.com/emails';
// Subscription license signing (ECDSA P-256 / ES256). The private key never
// leaves this server; the matching public key is embedded in the client app
// (js/config.js) so registers can verify a token entirely offline. Generate
// a keypair once — see docs/MIGRATION-SUPABASE.md "Subscription licensing".
const LICENSE_PRIVATE_KEY_PKCS8_B64 = process.env.LICENSE_PRIVATE_KEY_PKCS8_B64 || '';
const GRACE_DAYS = 5;

/* ------------------------------- storage -------------------------------- */
function emptyDB() {
  return {
    seq: 0, tenants: {}, products: {}, variations: {}, staff: {}, sales: {}, sale_items: {}, alerts: [],
    subscriptions: {}, subscription_audit_log: {}, devices: {},
    signup_requests: {}, login_failures: {}
  };
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
function upsertStaff(s) {
  const cur = db.staff[s.id] || {};
  db.staff[s.id] = touch(Object.assign(cur, s, { updated_at: s.updated_at || nowISO() }));
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

function upsertSubscription(s) {
  const cur = db.subscriptions[s.tenant_id] || {};
  db.subscriptions[s.tenant_id] = touch(Object.assign(cur, s, { updated_at: s.updated_at || nowISO() }));
}

/* ---------------------- subscription license signing -------------------- */
const { webcrypto } = crypto;
let _licenseKeyPromise = null;
function getLicensePrivateKey() {
  if (!LICENSE_PRIVATE_KEY_PKCS8_B64) return null;
  if (!_licenseKeyPromise) {
    const raw = Buffer.from(LICENSE_PRIVATE_KEY_PKCS8_B64, 'base64');
    _licenseKeyPromise = webcrypto.subtle.importKey(
      'pkcs8', raw, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  }
  return _licenseKeyPromise;
}
function b64url(bufOrString) {
  const buf = Buffer.isBuffer(bufOrString) ? bufOrString
    : Buffer.from(bufOrString instanceof ArrayBuffer ? Buffer.from(bufOrString) : String(bufOrString));
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
async function signLicenseToken(payload) {
  const key = await getLicensePrivateKey();
  if (!key) throw new Error('LICENSE_PRIVATE_KEY_PKCS8_B64 is not set on this server');
  const h = b64url(JSON.stringify({ alg: 'ES256', typ: 'LICENSE' }));
  const p = b64url(JSON.stringify(payload));
  const sig = await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, Buffer.from(h + '.' + p));
  return h + '.' + p + '.' + b64url(Buffer.from(sig));
}
// Look up (creating a default 3-day full-access trial if none exists yet, so
// a brand-new shop is immediately usable) and sign a license for a tenant.
async function issueLicense(tenantId) {
  let sub = db.subscriptions[tenantId];
  if (!sub) {
    const now = nowISO();
    const expires = new Date(Date.now() + 3 * 86400000).toISOString();
    const grace = new Date(new Date(expires).getTime() + GRACE_DAYS * 86400000).toISOString();
    sub = touch({
      tenant_id: tenantId, plan: 'trial', status: 'active', started_at: now,
      expires_at: expires, grace_until: grace,
      entitlements: { analytics: true, remote_sales: true, import_inventory: true, expiry_tracking: true },
      created_at: now
    });
    db.subscriptions[tenantId] = sub;
    const auditId = uid('slog');
    db.subscription_audit_log[auditId] = touch({
      id: auditId, tenant_id: tenantId, action: 'created', from_plan: null, to_plan: 'trial',
      from_expires: null, to_expires: expires, note: 'auto-issued 3-day trial', at: now
    });
    save();
  }
  const payload = {
    tenant_id: tenantId, plan: sub.plan, canceled: sub.status === 'canceled',
    expires_at: sub.expires_at, grace_until: sub.grace_until,
    entitlements: sub.entitlements || {}, issued_at: nowISO()
  };
  return signLicenseToken(payload);
}

/* ------------------------- device auth & scoping ------------------------
 * Every sync call must say who it is:
 *   X-Admin-Key: <ADMIN_KEY>   -> the owner's device: all shops.
 *   X-Device-Token: <token>    -> one shop only (issued by /api/login after a
 *                                 staff member's shop name + username + PIN
 *                                 check). Pulls are filtered to that shop and
 *                                 pushes touching any other shop are refused.
 * Tokens are HMAC-signed with a key derived from the license private key, so
 * no extra secret has to be configured. */
const TOKEN_SECRET = crypto.createHash('sha256')
  .update('device-token-v1:' + (LICENSE_PRIVATE_KEY_PKCS8_B64 || process.env.DEVICE_TOKEN_SECRET || 'dev-only-secret'))
  .digest();
function signDeviceToken(payload) {
  const p = b64url(JSON.stringify(payload));
  return p + '.' + b64url(crypto.createHmac('sha256', TOKEN_SECRET).update(p).digest());
}
function verifyDeviceToken(tok) {
  const parts = String(tok || '').split('.');
  if (parts.length !== 2) return null;
  const want = b64url(crypto.createHmac('sha256', TOKEN_SECRET).update(parts[0]).digest());
  const a = Buffer.from(want), b = Buffer.from(parts[1]);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try { return JSON.parse(Buffer.from(parts[0].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8')); }
  catch (e) { return null; }
}
function safeEqual(x, y) {
  const a = Buffer.from(String(x || '')), b = Buffer.from(String(y || ''));
  return a.length === b.length && a.length > 0 && crypto.timingSafeEqual(a, b);
}
// -> { scope: 'admin' } | { scope: 'tenant', tid, sid } | { error }
function authenticate(req) {
  const key = req.headers['x-admin-key'];
  if (key) return safeEqual(key, ADMIN_KEY) ? { scope: 'admin' } : { error: 'bad_admin_key' };
  const tok = req.headers['x-device-token'];
  if (!tok) return { error: 'no_credentials' };
  const t = verifyDeviceToken(tok);
  if (!t || !t.tid || !t.sid) return { error: 'invalid_token' };
  const staff = db.staff[t.sid];
  const tenant = db.tenants[t.tid];
  // Revoked when the staff member is removed/deactivated or the shop deleted.
  if (!staff || staff.tenant_id !== t.tid || !Number(staff.active == null ? 1 : staff.active) ||
      !tenant || tenant.status === 'deleted') return { error: 'revoked' };
  return { scope: 'tenant', tid: t.tid, sid: t.sid };
}
const norm = (s) => String(s || '').trim().replace(/\s+/g, ' ').toLowerCase();
function shopNameTaken(name, exceptTenantId) {
  const n = norm(name);
  return Object.values(db.tenants).some((t) => t.id !== exceptTenantId && t.status !== 'deleted' && norm(t.name) === n);
}
// Shop settings a manager may change from their own device; plan/feature
// switches, currency and status stay with the admin.
const ADMIN_ONLY_TENANT_FIELDS = ['status', 'currency', 'analytics_enabled', 'remote_sales_enabled',
  'import_inventory_enabled', 'expiry_tracking_enabled'];
// Decide whether a shop-scoped device may apply this change (mutating the
// payload to pin it to that shop). Admin devices may apply anything.
function authorizeChange(ch, auth) {
  if (auth.scope === 'admin') return true;
  const tid = auth.tid;
  const p = ch.payload || (ch.payload = {});
  const ownedOrNew = (map, id) => !map[id] || map[id].tenant_id === tid;
  switch (ch.entity) {
    case 'tenant': {
      if (ch.entity_id !== tid || !db.tenants[tid]) return false;
      ADMIN_ONLY_TENANT_FIELDS.forEach((f) => { delete p[f]; });
      if (p.name != null && shopNameTaken(p.name, tid)) delete p.name;
      p.id = tid;
      return true;
    }
    case 'product': {
      if (ch.op === 'delete') return !!db.products[ch.entity_id] && db.products[ch.entity_id].tenant_id === tid;
      if (p.product) {
        if (!ownedOrNew(db.products, p.product.id)) return false;
        p.product.tenant_id = tid;
      }
      for (const v of (p.variations || [])) {
        if (!ownedOrNew(db.variations, v.id)) return false;
        const prod = db.products[v.product_id];
        if (prod && prod.tenant_id !== tid) return false;
        v.tenant_id = tid;
      }
      return true;
    }
    case 'staff':
      if (!ownedOrNew(db.staff, ch.entity_id)) return false;
      p.tenant_id = tid; return true;
    case 'stock':
      return !!db.variations[ch.entity_id] && db.variations[ch.entity_id].tenant_id === tid;
    case 'sale': {
      if (!ownedOrNew(db.sales, ch.entity_id)) return false;
      if (p.sale) p.sale.tenant_id = tid;
      for (const it of (p.items || [])) {
        if (it.id && !ownedOrNew(db.sale_items, it.id)) return false;
        it.tenant_id = tid;
      }
      return true;
    }
    default: return false; // subscriptions etc. are admin-only
  }
}

/* ------------------------- sign-in & sign-up ----------------------------- */
const LOCK_AFTER = 8, LOCK_MS = 15 * 60 * 1000;
function hashPin(pin, salt) { return crypto.createHash('sha256').update(String(salt) + ':' + String(pin)).digest('hex'); }
function recordDevice(deviceId, tid, name) {
  if (!deviceId) return;
  const cur = db.devices[deviceId] || { device_id: deviceId, first_seen: nowISO() };
  db.devices[deviceId] = touch(Object.assign(cur, { tenant_id: tid, device_name: name || cur.device_name, last_seen: nowISO() }));
}
async function notifySignup(r) {
  if (!RESEND_API_KEY || !NOTIFY_EMAIL) return;
  const text = [
    'A new shop asked to join TS - POS:', '',
    'Shop: ' + r.shop_name, 'Owner: ' + r.owner_name, 'Phone: ' + r.phone,
    'Second phone: ' + (r.phone2 || '-'), 'Email: ' + (r.email || '-'),
    'Location: ' + (r.address || '-'), 'Currency: ' + r.currency, 'Username: ' + r.username, '',
    'Approve it in the app: Admin -> Sign-up requests.'
  ].join('\n');
  try {
    await fetch(RESEND_API_URL, {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + RESEND_API_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: NOTIFY_FROM, to: [NOTIFY_EMAIL], subject: 'New TS - POS sign-up: ' + r.shop_name, text })
    });
  } catch (e) { console.error('signup e-mail failed', e.message); }
}
const CURRENCIES = ['GYD', 'USD', 'EUR', 'GBP', 'GHS', 'NGN', 'KES', 'ZAR'];
// Returns an error string, or null when the sign-up form is acceptable.
function validateSignup(b) {
  const str = (v, max) => typeof v === 'string' && v.trim().length > 0 && v.length <= max;
  if (!str(b.owner_name, 80)) return 'Enter your name.';
  if (!str(b.shop_name, 80) || b.shop_name.trim().length < 2) return 'Enter your shop name.';
  if (!/^[0-9+()\-\s]{7,20}$/.test(String(b.phone || ''))) return 'Enter a valid phone number.';
  if (b.phone2 && !/^[0-9+()\-\s]{7,20}$/.test(String(b.phone2))) return 'Enter a valid second phone number.';
  if (b.email && !/^[^\s@]{1,64}@[^\s@]{1,100}\.[^\s@]{2,}$/.test(String(b.email))) return 'Enter a valid email address.';
  if (!str(b.address, 200)) return 'Enter your shop location.';
  if (!CURRENCIES.includes(b.currency)) return 'Choose a currency.';
  if (!/^[a-z0-9._-]{2,30}$/.test(String(b.username || ''))) return 'Username: 2-30 letters or numbers.';
  if (!/^[0-9a-f]{64}$/.test(String(b.pin_hash || '')) || !/^[0-9a-f]{8,64}$/.test(String(b.salt || ''))) return 'Invalid PIN.';
  return null;
}
function slugify(s) { return norm(s).replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40); }
function approveSignup(r) {
  const now = nowISO();
  const tid = uid('ten');
  upsertTenant({ id: tid, name: r.shop_name.trim(), slug: slugify(r.shop_name), phone: r.phone, email: r.email || null,
    address: r.address, currency: r.currency, vat_rate: 15, vat_inclusive: 1, vat_enabled: 1, status: 'active',
    created_at: now, updated_at: now });
  const sid = uid('stf');
  upsertStaff({ id: sid, tenant_id: tid, name: r.owner_name, username: r.username, pin_hash: r.pin_hash, salt: r.salt,
    role: 'manager', can_view_sales: 0, can_manage_inventory: 0, active: 1, created_at: now, updated_at: now });
  const expires = new Date(Date.now() + 3 * 86400000).toISOString();
  const grace = new Date(Date.now() + (3 + GRACE_DAYS) * 86400000).toISOString();
  upsertSubscription({ tenant_id: tid, plan: 'trial', status: 'active', started_at: now, expires_at: expires,
    grace_until: grace, entitlements: { analytics: true, remote_sales: true, import_inventory: true, expiry_tracking: true },
    created_at: now, updated_at: now });
  const aid = uid('slog');
  db.subscription_audit_log[aid] = touch({ id: aid, tenant_id: tid, action: 'created', from_plan: null, to_plan: 'trial',
    from_expires: null, to_expires: expires, note: 'Sign-up approved — 3-day trial', at: now });
  Object.assign(r, { status: 'approved', tenant_id: tid, decided_at: now });
  return tid;
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
    case 'staff': upsertStaff(Object.assign({ id: ch.entity_id }, p)); break;
    case 'subscription': upsertSubscription(Object.assign({ tenant_id: ch.entity_id }, p)); break;
    case 'subscription_audit': {
      const id = ch.entity_id;
      if (!db.subscription_audit_log[id]) db.subscription_audit_log[id] = touch(Object.assign({ id }, p));
      break;
    }
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
      db.sales[ch.entity_id] = touch(Object.assign(db.sales[ch.entity_id] || { received_at: nowISO() }, { id: ch.entity_id }, s));
      // Use the client-provided item id so replays don't duplicate line items.
      (p.items || []).forEach((it) => {
        const id = it.id || uid('si');
        db.sale_items[id] = touch(Object.assign(db.sale_items[id] || {}, it, { id, sale_id: ch.entity_id }));
      });
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
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Admin-Key, X-Device-Token',
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
  return safeEqual(auth, 'Bearer ' + ADMIN_TOKEN) || safeEqual(req.headers['x-admin-key'], ADMIN_KEY);
}

/* -------------------------------- routes -------------------------------- */
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;

  if (req.method === 'OPTIONS') return send(res, 204, '');

  // ---- Staff sign-in -> shop-scoped device token ----
  if (p === '/api/login' && req.method === 'POST') {
    const b = await readBody(req);
    const shop = norm(b.shop), user = norm(b.username);
    if (!shop || !user || !b.pin) return send(res, 400, { error: 'missing_fields' });
    const key = shop + '|' + user;
    const f = db.login_failures[key];
    if (f && f.locked_until && new Date(f.locked_until) > new Date()) {
      return send(res, 429, { error: 'locked', retry_after: f.locked_until });
    }
    const tenant = Object.values(db.tenants).find((t) => t.status !== 'deleted' && norm(t.name) === shop);
    const staff = tenant && Object.values(db.staff).find((s) =>
      s.tenant_id === tenant.id && norm(s.username) === user && Number(s.active == null ? 1 : s.active));
    if (!staff || hashPin(b.pin, staff.salt) !== staff.pin_hash) {
      const cur = db.login_failures[key] || { count: 0 };
      cur.count += 1;
      if (cur.count >= LOCK_AFTER) { cur.locked_until = new Date(Date.now() + LOCK_MS).toISOString(); cur.count = 0; }
      db.login_failures[key] = cur; save();
      return send(res, 401, { error: 'invalid_login' });
    }
    if (tenant.status === 'suspended') return send(res, 403, { error: 'suspended' });
    delete db.login_failures[key];
    recordDevice(b.device_id, tenant.id, b.device_name);
    save();
    return send(res, 200, {
      token: signDeviceToken({ tid: tenant.id, sid: staff.id, iat: nowISO() }),
      tenant_id: tenant.id, tenant_name: tenant.name
    });
  }

  // ---- Public sign-up request (owner approves it in Admin) ----
  if (p === '/api/signup' && req.method === 'POST') {
    const b = await readBody(req);
    if (b.website) return send(res, 200, { ok: true }); // honeypot: bots fill hidden fields
    const bad = validateSignup(b);
    if (bad) return send(res, 400, { error: 'invalid', message: bad });
    const pending = Object.values(db.signup_requests).filter((r) => r.status === 'pending');
    if (pending.length >= 500) return send(res, 429, { error: 'busy', message: 'Too many pending requests — please call us.' });
    if (pending.filter((r) => r.phone === b.phone).length >= 3) {
      return send(res, 429, { error: 'busy', message: 'You already have requests waiting — we will contact you soon.' });
    }
    if (shopNameTaken(b.shop_name) || pending.some((r) => norm(r.shop_name) === norm(b.shop_name))) {
      return send(res, 409, { error: 'shop_taken', message: 'That shop name is already registered. Please choose another.' });
    }
    const id = uid('sup');
    const r = { id, status: 'pending', created_at: nowISO() };
    ['owner_name', 'shop_name', 'phone', 'phone2', 'email', 'address', 'currency', 'username', 'pin_hash', 'salt']
      .forEach((k) => { r[k] = typeof b[k] === 'string' ? b[k].trim() : null; });
    r.username = r.username.toLowerCase();
    db.signup_requests[id] = r; save();
    await notifySignup(r);
    return send(res, 200, { ok: true });
  }

  // Everything below needs a device token or the admin key.
  const SCOPED = ['/api/sync', '/api/pull', '/api/license', '/api/whoami', '/api/shop-name-available',
    '/api/signups', '/api/signups/approve', '/api/signups/reject'];
  let auth = null;
  if (SCOPED.includes(p)) {
    auth = authenticate(req);
    if (auth.error) return send(res, 401, { error: auth.error });
  }

  if (p === '/api/whoami' && req.method === 'GET') {
    return send(res, 200, { scope: auth.scope, tenant_id: auth.tid || null });
  }

  if (p === '/api/shop-name-available' && req.method === 'GET') {
    const name = url.searchParams.get('name') || '';
    return send(res, 200, { available: !!name.trim() && !shopNameTaken(name, auth.tid || url.searchParams.get('tenant_id')) });
  }

  // ---- Sign-up review (admin only) ----
  if (p.startsWith('/api/signups')) {
    if (auth.scope !== 'admin') return send(res, 403, { error: 'admin_only' });
    if (p === '/api/signups' && req.method === 'GET') {
      const list = Object.values(db.signup_requests)
        .sort((a, b) => String(b.created_at).localeCompare(String(a.created_at))).slice(0, 100)
        .map((r) => { const o = Object.assign({}, r); delete o.pin_hash; delete o.salt; return o; });
      return send(res, 200, { requests: list });
    }
    const b = await readBody(req);
    const r = db.signup_requests[b.id];
    if (!r || r.status !== 'pending') return send(res, 404, { error: 'not_found' });
    if (p === '/api/signups/approve' && req.method === 'POST') {
      if (shopNameTaken(r.shop_name)) return send(res, 409, { error: 'shop_taken', message: 'A shop with this name already exists.' });
      const tid = approveSignup(r); save();
      return send(res, 200, { ok: true, tenant_id: tid });
    }
    if (p === '/api/signups/reject' && req.method === 'POST') {
      Object.assign(r, { status: 'rejected', decided_at: nowISO(), note: b.note || null }); save();
      return send(res, 200, { ok: true });
    }
  }

  // ---- Register push (each change checked against the device's shop) ----
  if (p === '/api/sync' && req.method === 'POST') {
    const body = await readBody(req);
    const applied = [], rejected = [];
    (body.changes || []).forEach((ch) => {
      try {
        if (!authorizeChange(ch, auth)) { rejected.push(ch.id); return; }
        applyChange(ch); applied.push(ch.id);
      } catch (e) { console.error('apply failed', e.message); }
    });
    save();
    return send(res, 200, { applied, rejected, low_stock: db.alerts.filter((a) => !a.resolved).length });
  }

  // ---- Register pull (per-table cursor based, filtered to the device's shop) ----
  if (p === '/api/pull' && req.method === 'GET') {
    const q = url.searchParams;
    // Each table filtered by its own cursor (falls back to legacy ?since=).
    const legacy = Number(q.get('since') || 0);
    const cur = (name) => Number(q.get(name + '_since') != null ? q.get(name + '_since') : legacy) || 0;
    const mine = auth.scope === 'admin' ? () => true : (x, col) => x[col || 'tenant_id'] === auth.tid;
    const pick = (map, name, col) => Object.values(map).filter((x) => (x.seq || 0) > cur(name) && mine(x, col));
    return send(res, 200, {
      cursor: db.seq,
      tenants: pick(db.tenants, 'tenants', 'id'),
      products: pick(db.products, 'products'),
      variations: pick(db.variations, 'variations'),
      staff: pick(db.staff, 'staff'),
      sales: pick(db.sales, 'sales'),
      sale_items: pick(db.sale_items, 'sale_items'),
      subscriptions: pick(db.subscriptions, 'subscriptions'),
      subscription_audit_log: pick(db.subscription_audit_log, 'subscription_audit_log'),
      devices: pick(db.devices, 'devices')
    });
  }

  // ---- Subscription license check-in (also records device visibility) ----
  if (p === '/api/license' && req.method === 'GET') {
    const q = url.searchParams;
    const tid = q.get('tenant_id');
    if (!tid) return send(res, 400, { error: 'tenant_id required' });
    if (auth.scope !== 'admin' && tid !== auth.tid) return send(res, 403, { error: 'wrong_shop' });
    recordDevice(q.get('device_id'), tid, q.get('device_name'));
    try {
      const token = await issueLicense(tid);
      save();
      return send(res, 200, { token });
    } catch (e) {
      return send(res, 500, { error: e.message });
    }
  }

  // ---- Low-stock alerts (reordering) ----
  if (p === '/api/alerts' && req.method === 'GET') {
    if (!requireAdmin(req)) return send(res, 401, { error: 'unauthorized' });
    const tid = url.searchParams.get('tenant_id');
    const list = db.alerts.filter((a) => !a.resolved && (!tid || a.tenant_id === tid));
    return send(res, 200, { alerts: list });
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
  if (ADMIN_KEY === 'change-me-admin-token') console.warn('  ⚠  Set ADMIN_KEY env var before deploying!');
  if (!LICENSE_PRIVATE_KEY_PKCS8_B64) console.warn('  ⚠  LICENSE_PRIVATE_KEY_PKCS8_B64 not set — /api/license will fail. See docs/MIGRATION-SUPABASE.md.');
});
