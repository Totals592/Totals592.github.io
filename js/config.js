/*
 * Totals POS - Shared configuration & domain helpers
 * ---------------------------------------------------------------------------
 * Money math, VAT calculation and tenant scoping used across every screen.
 */
window.Config = (function () {
  'use strict';

  const CURRENCY_SYMBOLS = { GYD: '$', GHS: '₵', USD: '$', EUR: '€', GBP: '£', NGN: '₦', KES: 'KSh', ZAR: 'R' };

  // Whole numbers show with no decimals (e.g. $12), fractional amounts keep two
  // (e.g. $12.50). Thousands are grouped with commas.
  function money(n, currency) {
    const sym = CURRENCY_SYMBOLS[currency] || (currency ? currency + ' ' : '');
    const v = Math.round((Number(n) || 0) * 100) / 100;
    const s = Number.isInteger(v) ? String(v) : v.toFixed(2);
    const parts = s.split('.');
    parts[0] = parts[0].replace(/\B(?=(\d{3})+(?!\d))/g, ',');
    return sym + parts.join('.');
  }

  /*
   * VAT is calculated one of two legally-recognised ways:
   *   - Inclusive: the shelf price already contains VAT, so we extract it.
   *       vat = total - total / (1 + rate)
   *   - Exclusive: VAT is added on top of the subtotal.
   *       vat = subtotal * rate
   */
  function vatBreakdown(lineTotal, ratePct, inclusive) {
    const rate = (Number(ratePct) || 0) / 100;
    if (rate <= 0) return { net: lineTotal, vat: 0, gross: lineTotal };
    if (inclusive) {
      const net = lineTotal / (1 + rate);
      return { net, vat: lineTotal - net, gross: lineTotal };
    }
    const vat = lineTotal * rate;
    return { net: lineTotal, vat, gross: lineTotal + vat };
  }

  /* Active tenant helpers ---------------------------------------------------*/
  function activeTenantId() { return DB.getSetting('active_tenant_id'); }
  function activeTenant() {
    const id = activeTenantId();
    return id ? DB.get('SELECT * FROM tenants WHERE id = ?', [id]) : null;
  }
  function setActiveTenant(id) { DB.setSetting('active_tenant_id', id); }

  // Your cloud sync endpoint, baked in so every device auto-connects. New
  // installs use this automatically; an admin can override or clear it (an
  // explicit empty value = run offline) in Admin → Cloud sync.
  const DEFAULT_API_BASE = 'https://wisnnbbodcertkaebojo.functions.supabase.co';

  function apiBase() {
    const s = DB.getSetting('api_base'); // null = never set → use default; '' = admin turned it off
    let base = (s === null || s === undefined) ? DEFAULT_API_BASE : s;
    // The default is a placeholder until baked with the real URL — ignore it.
    if (base && base.indexOf('REPLACE-WITH-YOUR-REF') !== -1) base = '';
    return (base || '').replace(/\/+$/, '');
  }
  function deviceName() { return DB.getSetting('device_name') || 'Register 1'; }
  // Stable id for THIS device/browser (local only, never synced as a row).
  function deviceId() {
    let id = DB.getSetting('device_id');
    if (!id) {
      id = 'dev_' + (crypto.randomUUID ? crypto.randomUUID() : Date.now().toString(36) + Math.random().toString(36).slice(2));
      DB.setSetting('device_id', id);
    }
    return id;
  }
  function cashierName() { return DB.getSetting('cashier_name') || 'Cashier'; }
  function adminPin() { return DB.getSetting('admin_pin') || '1234'; }

  // Effective selling price after any per-item discount set in inventory.
  function effectivePrice(v) {
    const p = Number(v.price) || 0;
    const dv = Number(v.discount_value) || 0;
    let out = p;
    if (v.discount_type === 'percent' && dv > 0) out = p * (1 - dv / 100);
    else if (v.discount_type === 'amount' && dv > 0) out = p - dv;
    return Math.max(0, Math.round(out * 100) / 100);
  }
  function hasDiscount(v) {
    return (v.discount_type === 'percent' || v.discount_type === 'amount') && Number(v.discount_value) > 0;
  }

  /* Next receipt number, per tenant, e.g. RCT-000042 -------------------------*/
  function nextReceiptNo(tenantId, slug) {
    const key = 'receipt_seq_' + tenantId;
    const n = parseInt(DB.getSetting(key) || '0', 10) + 1;
    DB.setSetting(key, n);
    const prefix = (slug || 'RCT').slice(0, 6).toUpperCase().replace(/[^A-Z0-9]/g, '');
    return (prefix || 'RCT') + '-' + String(n).padStart(6, '0');
  }

  // Local calendar date as YYYY-MM-DD (used to reset the daily order number).
  function todayKey(d) {
    d = d || new Date();
    const p = (n) => String(n).padStart(2, '0');
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate());
  }

  /*
   * Daily order number for food service. Counts up per tenant and starts again
   * at 1 each calendar day, so tickets read "Order #1, #2, …" every morning.
   */
  function nextOrderNo(tenantId) {
    const day = todayKey();
    const key = 'order_seq_' + tenantId + '_' + day;
    const n = parseInt(DB.getSetting(key) || '0', 10) + 1;
    DB.setSetting(key, n);
    return n;
  }

  function escapeHtml(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  /* Staff credential hashing (PINs are never stored in the clear) ----------*/
  function randomSalt() {
    const a = new Uint8Array(12); crypto.getRandomValues(a);
    return Array.from(a).map((b) => b.toString(16).padStart(2, '0')).join('');
  }
  async function hashPin(pin, salt) {
    const data = new TextEncoder().encode(String(salt) + ':' + String(pin));
    const buf = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  /* Login session (device-local, not part of the synced database) ----------*/
  const SESSION_KEY = 'totals_session';
  function currentSession() {
    try { return JSON.parse(localStorage.getItem(SESSION_KEY) || 'null'); } catch (e) { return null; }
  }
  function setSession(s) {
    if (s) localStorage.setItem(SESSION_KEY, JSON.stringify(s));
    else localStorage.removeItem(SESSION_KEY);
  }

  // Cashier name shown on receipts = the signed-in staff member.
  function cashierNameResolved() {
    const s = currentSession();
    return (s && s.name) || cashierName();
  }
  function currentRole() { const s = currentSession(); return (s && s.role) || 'cashier'; }

  /* ---------------------------------------------------------------------
   * Subscription licensing
   * -----------------------------------------------------------------------
   * The cloud signs a small token (ECDSA P-256 / ES256, header.payload.sig,
   * base64url) proving a tenant's plan, expiry and grace-period dates. Only
   * the cloud holds the PRIVATE key (a Supabase secret); this public key is
   * safe to ship — it can verify a signature but never forge one. The token
   * is verified and its dates evaluated entirely on-device, so licensing
   * works fully offline once a token has been cached: no sale ever needs a
   * network call. Only *renewing* that cached token (picking up a plan
   * change, extension, or cancellation) needs occasional connectivity.
   * ------------------------------------------------------------------- */
  const LICENSE_PUBLIC_KEY_SPKI_B64 =
    'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmAewAuLvcsTT60/sDlwPRfNQ/fxVgCgNIUUTlc/BcFceVvwHr4wHPL+DZdLckkOxwmhpyKjViHz3jf8gjLp8Sw==';

  let _licensePubKey = null;
  async function importLicensePublicKey() {
    if (_licensePubKey) return _licensePubKey;
    const raw = Uint8Array.from(atob(LICENSE_PUBLIC_KEY_SPKI_B64), (c) => c.charCodeAt(0));
    _licensePubKey = await crypto.subtle.importKey(
      'spki', raw.buffer, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    return _licensePubKey;
  }
  function b64urlToBytes(s) {
    s = String(s || '').replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  }

  // Verify a cached token's signature and decode its payload. Returns null
  // for anything malformed, tampered, or signed by a different key — never
  // throws, so a corrupt cache can never crash the app.
  async function verifyLicenseToken(token) {
    try {
      const parts = String(token || '').split('.');
      if (parts.length !== 3) return null;
      const [h, p, s] = parts;
      const key = await importLicensePublicKey();
      const data = new TextEncoder().encode(h + '.' + p);
      const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, b64urlToBytes(s), data);
      if (!ok) return null;
      return JSON.parse(new TextDecoder().decode(b64urlToBytes(p)));
    } catch (e) { return null; }
  }

  // Turn a verified payload into a live state relative to THIS device's
  // clock — dates are only meaningful evaluated "now", not frozen at the
  // moment the token was issued (it may be days or weeks old).
  //   active  -> normal use; warning=true inside the last 5 days
  //   grace   -> past expiry, still usable, inside the 5-day grace window
  //   locked  -> past grace (or explicitly canceled) — hard lock
  function computeLicenseState(payload) {
    if (!payload) return { known: false, state: 'active', plan: null, entitlements: {} };
    const now = new Date();
    const expiresAt = payload.expires_at ? new Date(payload.expires_at) : null;
    const graceUntil = payload.grace_until ? new Date(payload.grace_until) : null;
    let state;
    if (payload.canceled) state = 'locked';
    else if (!expiresAt || now <= expiresAt) state = 'active';
    else if (graceUntil && now <= graceUntil) state = 'grace';
    else state = 'locked';
    const daysLeft = expiresAt ? Math.ceil((expiresAt - now) / 86400000) : null;
    const graceDaysLeft = graceUntil ? Math.ceil((graceUntil - now) / 86400000) : null;
    return {
      known: true, state, plan: payload.plan || 'trial',
      entitlements: payload.entitlements || {},
      expiresAt, graceUntil, daysLeft, graceDaysLeft,
      warning: state === 'active' && daysLeft != null && daysLeft <= 5,
      tenantId: payload.tenant_id
    };
  }

  // Last-computed state per tenant id, kept in memory so the UI can read it
  // synchronously during render without awaiting crypto on every paint.
  // {} (unknown/active/no entitlements) until the first refresh completes —
  // a brand-new, never-yet-synced device is never blocked before licensing
  // has had a chance to activate.
  const _licenseStates = {};
  function getLicenseState(tenantId) {
    const id = tenantId || activeTenantId();
    return _licenseStates[id] || { known: false, state: 'active', plan: null, entitlements: {} };
  }
  // Re-verify the cached token for a tenant and refresh the in-memory state.
  // Called at boot and after every sync; safe to call anytime (idempotent).
  async function refreshLicenseState(tenantId) {
    const id = tenantId || activeTenantId();
    if (!id) return getLicenseState(id);
    const token = DB.getSetting('license_token_' + id);
    const payload = await verifyLicenseToken(token);
    const st = computeLicenseState(payload);
    _licenseStates[id] = st;
    return st;
  }

  return {
    CURRENCY_SYMBOLS, money, vatBreakdown,
    activeTenantId, activeTenant, setActiveTenant,
    apiBase, deviceName, deviceId, cashierName: cashierNameResolved, adminPin,
    DEFAULT_API_BASE, effectivePrice, hasDiscount,
    nextReceiptNo, nextOrderNo, todayKey, escapeHtml,
    randomSalt, hashPin, currentSession, setSession, currentRole,
    verifyLicenseToken, getLicenseState, refreshLicenseState
  };
})();
