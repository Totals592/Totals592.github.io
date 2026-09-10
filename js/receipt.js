/*
 * Totals POS - Receipt generation
 * ---------------------------------------------------------------------------
 * Produces a legally-compliant cash receipt containing: business name, TIN,
 * contact details, physical location, an itemised list with quantities and
 * prices, the VAT breakdown (inclusive), totals, cash tendered and change.
 * Rendered for an 80mm thermal printer and printable straight from the browser.
 */
window.Receipt = (function () {
  'use strict';

  function build(sale, items, tenant) {
    const c = tenant.currency;
    const e = Config.escapeHtml;
    const dt = new Date(sale.created_at);
    // SKU is intentionally NOT printed on the customer receipt.
    const rows = items.map((it) => `
      <tr>
        <td class="l">${e(it.name)}</td>
        <td class="c">${it.qty}</td>
        <td class="r">${Config.money(it.unit_price, c)}</td>
        <td class="r">${Config.money(it.line_total, c)}</td>
      </tr>`).join('');

    const vatLabel = sale.vat_inclusive
      ? `VAT (${sale.vat_rate}% incl.)`
      : `VAT (${sale.vat_rate}%)`;

    // A line prints only if it applies AND the shop chose to show it.
    const showVat = Number(sale.vat_amount) > 0 && tenant.vat_show_receipt !== 0;
    const showSvc = Number(sale.service_charge) > 0 && tenant.service_charge_show_receipt !== 0;
    const svcLabel = `Service charge (${sale.service_charge_rate || 0}%)`;

    return `
    <div class="rcpt">
      <div class="hdr">
        ${tenant.logo && tenant.logo_on_receipt !== 0 ? `<img class="logo" src="${e(tenant.logo)}" alt="">` : ''}
        <div class="biz">${e(tenant.name)}</div>
        ${tenant.address ? `<div class="line">${e(tenant.address)}</div>` : ''}
        ${tenant.phone ? `<div class="line">Tel: ${e(tenant.phone)}</div>` : ''}
        ${tenant.email ? `<div class="line">${e(tenant.email)}</div>` : ''}
        ${tenant.tin ? `<div class="line"><b>TIN: ${e(tenant.tin)}</b></div>` : ''}
      </div>
      <div class="rule"></div>
      ${sale.order_no != null && tenant.order_no_on_receipt !== 0 ? `<div class="order">ORDER #${e(sale.order_no)}</div>` : ''}
      <div class="meta">
        <div><span>Receipt</span><span>${e(sale.receipt_no)}</span></div>
        <div><span>Date</span><span>${dt.toLocaleString()}</span></div>
        <div><span>Cashier</span><span>${e(sale.cashier || '')}</span></div>
        <div><span>Payment</span><span>CASH</span></div>
      </div>
      <div class="rule"></div>
      <table class="items">
        <thead><tr><th class="l">Item</th><th class="c">Qty</th><th class="r">Price</th><th class="r">Total</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
      <div class="rule"></div>
      <div class="totals">
        <div><span>Subtotal (net)</span><span>${Config.money(sale.subtotal - 0, c)}</span></div>
        ${showVat ? `<div><span>${vatLabel}</span><span>${Config.money(sale.vat_amount, c)}</span></div>` : ''}
        ${showSvc ? `<div><span>${svcLabel}</span><span>${Config.money(sale.service_charge, c)}</span></div>` : ''}
        <div class="grand"><span>TOTAL</span><span>${Config.money(sale.total, c)}</span></div>
        <div><span>Cash</span><span>${Config.money(sale.cash_received, c)}</span></div>
        <div><span>Change</span><span>${Config.money(sale.change_due, c)}</span></div>
      </div>
      <div class="rule"></div>
      <div class="ftr">
        <div>${e(tenant.receipt_footer || 'Thank you!')}</div>
        ${showVat ? `<div class="small">Price is VAT ${sale.vat_inclusive ? 'inclusive' : 'exclusive'}. This is your official receipt.</div>` : '<div class="small">This is your official receipt.</div>'}
        <div class="small">Powered by Totals POS</div>
      </div>
    </div>`;
  }

  const PRINT_CSS = `
    * { box-sizing: border-box; }
    body { margin:0; background:#fff; color:#000; font-family:'Courier New',monospace; }
    .rcpt { width:280px; margin:0 auto; padding:10px 8px; font-size:12px; }
    .hdr { text-align:center; }
    .logo { max-width:120px; max-height:60px; margin-bottom:4px; }
    .biz { font-size:16px; font-weight:bold; }
    .line { font-size:11px; }
    .rule { border-top:1px dashed #000; margin:6px 0; }
    .meta div, .totals div { display:flex; justify-content:space-between; }
    table.items { width:100%; border-collapse:collapse; }
    table.items th, table.items td { padding:2px 0; font-size:11px; vertical-align:top; }
    .l{ text-align:left; } .c{ text-align:center; } .r{ text-align:right; }
    .order { text-align:center; font-size:22px; font-weight:bold; letter-spacing:1px; margin:4px 0; }
    .totals .grand { font-size:14px; font-weight:bold; border-top:1px solid #000; border-bottom:1px solid #000; padding:3px 0; margin:3px 0; }
    .ftr { text-align:center; margin-top:6px; }
    .small { font-size:9px; color:#333; margin-top:3px; }
    @media print { @page { margin:4mm; } }
  `;

  function html(sale, items, tenant) {
    return `<!doctype html><html><head><meta charset="utf-8"><title>${Config.escapeHtml(sale.receipt_no)}</title><style>${PRINT_CSS}</style></head><body>${build(sale, items, tenant)}<script>window.onload=function(){setTimeout(function(){window.print();},250);};<\/script></body></html>`;
  }

  function print(sale, items, tenant) {
    const w = window.open('', '_blank', 'width=360,height=640');
    if (!w) { alert('Please allow pop-ups to print receipts.'); return; }
    w.document.open();
    w.document.write(html(sale, items, tenant));
    w.document.close();
  }

  return { build, html, print, PRINT_CSS };
})();
