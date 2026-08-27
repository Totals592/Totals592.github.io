/*
 * Totals POS - Shared configuration & domain helpers
 * ---------------------------------------------------------------------------
 * Money math, VAT calculation and tenant scoping used across every screen.
 */
window.Config = (function () {
  'use strict';

  const CURRENCY_SYMBOLS = { GHS: '₵', USD: '$', EUR: '€', GBP: '£', NGN: '₦', KES: 'KSh', ZAR: 'R' };

  function money(n, currency) {
    const sym = CURRENCY_SYMBOLS[currency] || (currency ? currency + ' ' : '');
    const v = (Math.round((Number(n) || 0) * 100) / 100).toFixed(2);
    return sym + v.replace(/\B(?=(\d{3})+(?!\d))/g, ',');
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

  function apiBase() { return (DB.getSetting('api_base') || '').replace(/\/+$/, ''); }
  function deviceName() { return DB.getSetting('device_name') || 'Register 1'; }
  function cashierName() { return DB.getSetting('cashier_name') || 'Cashier'; }
  function adminPin() { return DB.getSetting('admin_pin') || '1234'; }

  /* Next receipt number, per tenant, e.g. RCT-000042 -------------------------*/
  function nextReceiptNo(tenantId, slug) {
    const key = 'receipt_seq_' + tenantId;
    const n = parseInt(DB.getSetting(key) || '0', 10) + 1;
    DB.setSetting(key, n);
    const prefix = (slug || 'RCT').slice(0, 6).toUpperCase().replace(/[^A-Z0-9]/g, '');
    return (prefix || 'RCT') + '-' + String(n).padStart(6, '0');
  }

  function escapeHtml(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  return {
    CURRENCY_SYMBOLS, money, vatBreakdown,
    activeTenantId, activeTenant, setActiveTenant,
    apiBase, deviceName, cashierName, adminPin,
    nextReceiptNo, escapeHtml
  };
})();
