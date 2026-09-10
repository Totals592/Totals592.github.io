/*
 * Totals POS - Application controller
 * ---------------------------------------------------------------------------
 * Wires the UI to the local SQLite database, the sync engine and receipts.
 */
(function () {
  'use strict';

  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const money = (n) => Config.money(n, (Config.activeTenant() || {}).currency || 'GYD');
  const esc = Config.escapeHtml;

  /* ---------------- Toasts & modal ---------------- */
  function toast(msg, kind) {
    const t = document.createElement('div');
    t.className = 'toast ' + (kind || '');
    t.textContent = msg;
    $('#toasts').appendChild(t);
    setTimeout(() => t.remove(), 2600);
  }
  function openModal(html, big) {
    const m = $('#modal');
    m.className = 'modal' + (big ? ' big' : '');
    m.innerHTML = html;
    $('#modalBack').classList.add('open');
  }
  function closeModal() {
    if (modalCleanup) { try { modalCleanup(); } catch (e) {} modalCleanup = null; }
    $('#modalBack').classList.remove('open'); $('#modal').innerHTML = '';
  }
  $('#modalBack').addEventListener('click', (e) => { if (e.target.id === 'modalBack') closeModal(); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeModal(); });

  /* ---------------- Cart state ---------------- */
  let cart = []; // {variation_id, product_id, name, sku, unit_price, qty, track_stock, stock}
  let modalCleanup = null; // releases the camera when a scanner modal closes

  function cartAdd(v, p) {
    const line = cart.find((c) => c.variation_id === v.id);
    if (line) {
      if (v.track_stock && line.qty + 1 > v.stock) { toast('Not enough stock', 'err'); return; }
      line.qty += 1;
    } else {
      if (v.track_stock && v.stock < 1) { toast('Out of stock', 'err'); return; }
      cart.push({
        variation_id: v.id, product_id: p.id,
        name: p.name + (v.name && v.name !== 'Default' ? ' · ' + v.name : ''),
        sku: v.sku, unit_price: Config.effectivePrice(v), qty: 1,
        track_stock: !!v.track_stock, stock: v.stock
      });
    }
    renderCart();
  }
  function cartSetQty(id, delta) {
    const line = cart.find((c) => c.variation_id === id);
    if (!line) return;
    const next = line.qty + delta;
    if (next <= 0) { cart = cart.filter((c) => c.variation_id !== id); }
    else if (line.track_stock && next > line.stock) { toast('Not enough stock', 'err'); return; }
    else line.qty = next;
    renderCart();
  }
  function cartTotals() {
    const t = Config.activeTenant();
    const itemsGross = cart.reduce((s, c) => s + c.unit_price * c.qty, 0);
    const vatOn = !!t.vat_enabled && Number(t.vat_rate) > 0;
    const svcOn = !!t.service_charge_enabled && Number(t.service_charge_rate) > 0;

    // VAT is applied to the item lines; the service charge is a separate add-on.
    let itemsNet, vat, itemsTotal;
    if (vatOn && t.vat_inclusive) {
      const b = Config.vatBreakdown(itemsGross, t.vat_rate, true);
      itemsNet = b.net; vat = b.vat; itemsTotal = itemsGross;
    } else if (vatOn) {
      const b = Config.vatBreakdown(itemsGross, t.vat_rate, false);
      itemsNet = b.net; vat = b.vat; itemsTotal = b.gross;
    } else {
      itemsNet = itemsGross; vat = 0; itemsTotal = itemsGross;
    }
    const service = svcOn ? itemsGross * (Number(t.service_charge_rate) / 100) : 0;
    const total = itemsTotal + service;
    return {
      itemsGross, itemsNet, itemsTotal, vat, service, total,
      vatOn, svcOn, count: cart.reduce((s, c) => s + c.qty, 0)
    };
  }
  function renderCart() {
    const box = $('#cartItems');
    const t = Config.activeTenant();
    if (!cart.length) {
      box.innerHTML = '<div class="empty">Tap a product to start a sale.</div>';
    } else {
      box.innerHTML = cart.map((c) => `
        <div class="citem">
          <div>
            <div class="t">${esc(c.name)}</div>
            <div class="s">${c.sku ? esc(c.sku) + ' · ' : ''}${money(c.unit_price)}</div>
            <div class="qty">
              <button data-dec="${c.variation_id}">−</button>
              <span>${c.qty}</span>
              <button data-inc="${c.variation_id}">+</button>
            </div>
          </div>
          <div class="lt">${money(c.unit_price * c.qty)}</div>
        </div>`).join('');
    }
    const tot = cartTotals();
    $('#cartCount').textContent = tot.count + ' item' + (tot.count === 1 ? '' : 's');
    $('#sumNet').textContent = money(tot.itemsNet);
    // VAT row (hidden entirely when VAT is switched off for this shop).
    $('#vatRow').style.display = tot.vatOn ? '' : 'none';
    $('#sumVat').textContent = money(tot.vat);
    $('#vatLabel').textContent = `VAT (${t.vat_rate}%${t.vat_inclusive ? ' incl.' : ''})`;
    // Service-charge row (hidden when off).
    $('#svcRow').style.display = tot.svcOn ? '' : 'none';
    $('#sumSvc').textContent = money(tot.service);
    $('#svcLabel').textContent = `Service charge (${t.service_charge_rate}%)`;
    $('#sumTotal').textContent = money(tot.total);
    $('#chargeBtn').disabled = cart.length === 0;
    $('#chargeBtn').textContent = cart.length ? 'Charge ' + money(tot.total) : 'Charge';
  }

  /* ---------------- POS rendering ---------------- */
  let activeCat = 'All';
  function loadProducts() {
    const tid = Config.activeTenantId();
    const prods = DB.all(
      `SELECT * FROM products WHERE tenant_id = ? AND active = 1 ORDER BY sort, name`, [tid]);
    prods.forEach((p) => {
      p.variations = DB.all(
        `SELECT * FROM variations WHERE product_id = ? AND active = 1 ORDER BY price`, [p.id]);
    });
    return prods.filter((p) => p.variations.length);
  }
  function renderPOS() {
    const prods = loadProducts();
    const cats = ['All', ...Array.from(new Set(prods.map((p) => p.category || 'General')))];
    if (!cats.includes(activeCat)) activeCat = 'All';
    $('#cats').innerHTML = cats.map((c) =>
      `<button class="chip ${c === activeCat ? 'active' : ''}" data-cat="${esc(c)}">${esc(c)}</button>`).join('');

    const shown = prods.filter((p) => activeCat === 'All' || p.category === activeCat);
    $('#tiles').innerHTML = shown.map((p) => {
      const v = p.variations[0];
      const eff = (x) => Config.effectivePrice(x);
      const priceLabel = p.variations.length > 1
        ? 'from ' + money(Math.min(...p.variations.map(eff)))
        : money(eff(v));
      const dealt = p.variations.some((x) => Config.hasDiscount(x));
      const stock = p.variations.reduce((s, x) => s + (x.track_stock ? x.stock : Infinity), 0);
      const tracked = p.variations.some((x) => x.track_stock);
      const low = tracked && stock <= Math.max(...p.variations.map((x) => x.low_stock_threshold || 0));
      const out = tracked && stock <= 0;
      return `<button class="tile ${out ? 'out' : ''}" data-prod="${p.id}">
        <span class="swatch" style="background:${esc(p.color || '#334155')}"></span>
        ${p.image ? `<span class="img" style="background-image:url('${esc(p.image)}')"></span>` : ''}
        ${low ? `<span class="low">${out ? 'Out' : 'Low: ' + stock}</span>` : ''}
        ${dealt ? '<span class="deal">DEAL</span>' : ''}
        <span class="name">${esc(p.name)}</span>
        <span class="price">${priceLabel}</span>
      </button>`;
    }).join('') || '<p class="muted">No products yet. Add some in the Inventory tab.</p>';
  }

  function pickProduct(pid) {
    const p = DB.get('SELECT * FROM products WHERE id = ?', [pid]);
    const vars = DB.all('SELECT * FROM variations WHERE product_id = ? AND active = 1 ORDER BY price', [pid]);
    if (vars.length === 1) { cartAdd(vars[0], p); return; }
    openModal(`
      <header><h3>${esc(p.name)}</h3><button class="x" data-close>×</button></header>
      <div class="body">
        <p class="muted">Choose a variation</p>
        <div class="tiles">
          ${vars.map((v) => {
            const out = v.track_stock && v.stock <= 0;
            const eff = Config.effectivePrice(v);
            const priceHtml = Config.hasDiscount(v)
              ? `<span class="price">${money(eff)} <span class="was">${money(v.price)}</span></span>`
              : `<span class="price">${money(eff)}</span>`;
            return `<button class="tile ${out ? 'out' : ''}" data-var="${v.id}" ${out ? 'disabled' : ''}>
              <span class="name">${esc(v.name)}</span>
              ${priceHtml}
              ${v.track_stock ? `<span class="s muted">${v.stock} in stock</span>` : ''}
            </button>`;
          }).join('')}
        </div>
      </div>`);
    $$('[data-var]', $('#modal')).forEach((b) => b.addEventListener('click', () => {
      const v = vars.find((x) => x.id === b.dataset.var);
      cartAdd(v, p); closeModal();
    }));
    $('[data-close]', $('#modal')).addEventListener('click', closeModal);
  }

  /* ---------------- Barcode scanning ---------------- */

  // Add a scanned code to the cart. Returns the matched row, or null.
  function addByBarcode(code) {
    const row = Scan.lookup(code);
    if (!row) { toast('No item for code ' + code, 'err'); return null; }
    if (row.track_stock && row.stock <= 0) { toast(row.product_name + ' is out of stock', 'err'); return row; }
    cartAdd(row, { id: row.pid, name: row.product_name });
    const label = row.product_name + (row.name && row.name !== 'Default' ? ' · ' + row.name : '');
    toast('Added ' + label + ' — ' + money(row.price), 'ok');
    return row;
  }

  /*
   * Reusable camera scanner modal.
   * opts: { title, continuous, onCode }. When continuous is true the modal
   * stays open after each read (cashier scans many items); otherwise it closes
   * on the first successful read. Includes a manual-entry fallback field.
   */
  function openScanner(opts) {
    opts = opts || {};
    const supported = Scan.cameraSupported();
    openModal(`
      <header><h3>${esc(opts.title || 'Scan barcode')}</h3><button class="x" data-close>×</button></header>
      <div class="body">
        <div class="scanner">
          <video id="scanVideo" playsinline muted></video>
          <div class="scan-reticle"></div>
        </div>
        <div id="scanStatus" class="hint center">${supported ? 'Point the camera at a barcode…' : 'Camera unavailable — type the code below.'}</div>
        <label>Or enter code manually</label>
        <div class="toolbar">
          <input class="grow" id="scanManual" inputmode="numeric" placeholder="Barcode / SKU" autocomplete="off">
          <button class="btn brand" id="scanManualBtn">Enter</button>
        </div>
      </div>
      <div class="foot"><button class="btn ghost" data-close>Done</button></div>`);
    const m = $('#modal');
    let stop = null;
    let lastCode = ''; let lastAt = 0;

    function handle(code) {
      const now = Date.now();
      if (code === lastCode && now - lastAt < 1500) return; // debounce repeats
      lastCode = code; lastAt = now;
      if (navigator.vibrate) { try { navigator.vibrate(60); } catch (e) {} }
      if (opts.continuous) {
        // Stay open so the cashier can scan several items in a row.
        if (opts.onCode) opts.onCode(code);
        const st = $('#scanStatus', m);
        if (st) st.textContent = 'Last scan: ' + code;
      } else {
        // Release the camera and close THIS modal first, so onCode is free to
        // open its own modal (e.g. the product editor) without being clobbered.
        cleanup(); modalCleanup = null; closeModal();
        if (opts.onCode) opts.onCode(code);
      }
    }
    function cleanup() { if (stop) { try { stop(); } catch (e) {} stop = null; } }
    function cleanupAndClose() { cleanup(); closeModal(); }

    $$('[data-close]', m).forEach((b) => b.addEventListener('click', cleanupAndClose));
    $('#scanManualBtn', m).addEventListener('click', () => {
      const field = $('#scanManual', m);
      const v = field ? field.value.trim() : '';
      if (!v) return;
      handle(v);
      const again = $('#scanManual', m); // may be gone if the modal closed
      if (again) { again.value = ''; again.focus(); }
    });
    $('#scanManual', m).addEventListener('keydown', (e) => { if (e.key === 'Enter') $('#scanManualBtn', m).click(); });

    if (supported) {
      Scan.startCamera($('#scanVideo', m), handle)
        .then((s) => { stop = s; })
        .catch((err) => {
          const st = $('#scanStatus', m);
          if (st) st.textContent = (err && err.message) || 'Could not start the camera. Use manual entry.';
        });
    } else {
      setTimeout(() => $('#scanManual', m) && $('#scanManual', m).focus(), 60);
    }
    // Ensure the camera is released if the modal is dismissed another way.
    modalCleanup = cleanup;
  }

  /* ---------------- Charge (cash) ---------------- */
  function openCharge() {
    if (!cart.length) return;
    const tot = cartTotals();
    let entered = '';
    const notes = [1, 2, 5, 10, 20, 50, 100, 200];
    openModal(`
      <header><h3>Cash payment</h3><button class="x" data-close>×</button></header>
      <div class="body">
        <div class="row summary"><div class="row total" style="display:flex;justify-content:space-between;width:100%"><span>Total due</span><span>${money(tot.total)}</span></div></div>
        <label>Cash received</label>
        <div class="cash-display" id="cashDisplay">${money(0)}</div>
        <div class="quick-cash">
          <button class="btn" data-exact>Exact ${money(tot.total)}</button>
          ${notes.map((n) => `<button class="btn" data-note="${n}">+${money(n)}</button>`).join('')}
        </div>
        <div class="keypad">
          ${[1,2,3,4,5,6,7,8,9].map((d) => `<button data-d="${d}">${d}</button>`).join('')}
          <button data-d="00">00</button><button data-d="0">0</button><button data-back>⌫</button>
        </div>
        <div class="row" style="display:flex;justify-content:space-between;margin-top:12px;font-size:20px;font-weight:800">
          <span>Change</span><span id="changeDue">${money(0)}</span>
        </div>
      </div>
      <div class="foot">
        <button class="btn ghost" data-close>Cancel</button>
        <button class="charge" id="completeBtn" style="width:auto" disabled>Complete sale</button>
      </div>`, false);

    function refresh() {
      const cash = (parseInt(entered || '0', 10)) / 100;
      $('#cashDisplay').textContent = money(cash);
      const change = cash - tot.total;
      $('#changeDue').textContent = money(Math.max(0, change));
      $('#completeBtn').disabled = cash + 1e-9 < tot.total;
    }
    const m = $('#modal');
    $$('[data-d]', m).forEach((b) => b.addEventListener('click', () => { entered += b.dataset.d; refresh(); }));
    $('[data-back]', m).addEventListener('click', () => { entered = entered.slice(0, -1); refresh(); });
    $('[data-exact]', m).addEventListener('click', () => { entered = String(Math.round(tot.total * 100)); refresh(); });
    $$('[data-note]', m).forEach((b) => b.addEventListener('click', () => {
      entered = String((parseInt(entered || '0', 10)) + parseInt(b.dataset.note, 10) * 100); refresh();
    }));
    $$('[data-close]', m).forEach((b) => b.addEventListener('click', closeModal));
    $('#completeBtn').addEventListener('click', () => completeSale((parseInt(entered || '0', 10)) / 100, tot));
    refresh();
  }

  function completeSale(cash, tot) {
    const t = Config.activeTenant();
    const saleId = DB.uid('sale');
    const receiptNo = Config.nextReceiptNo(t.id, t.slug);
    const orderNo = Config.nextOrderNo(t.id);      // resets daily
    const orderDate = Config.todayKey();
    const now = DB.nowISO();
    const change = cash - tot.total;

    DB.run(`INSERT INTO sales(id,tenant_id,receipt_no,order_no,order_date,subtotal,vat_amount,total,cash_received,change_due,
             item_count,cashier,vat_inclusive,vat_rate,service_charge,service_charge_rate,currency,status,synced,created_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [saleId, t.id, receiptNo, orderNo, orderDate, tot.itemsNet, tot.vat, tot.total, cash, change, tot.count,
       Config.cashierName(), t.vat_inclusive ? 1 : 0, tot.vatOn ? t.vat_rate : 0,
       tot.service, tot.svcOn ? t.service_charge_rate : 0, t.currency, 'completed', 0, now]);

    const items = cart.map((c) => {
      const id = DB.uid('si');
      DB.run(`INSERT INTO sale_items(id,sale_id,tenant_id,product_id,variation_id,name,sku,qty,unit_price,line_total)
              VALUES(?,?,?,?,?,?,?,?,?,?)`,
        [id, saleId, t.id, c.product_id, c.variation_id, c.name, c.sku, c.qty, c.unit_price, c.unit_price * c.qty]);
      // Real-time stock decrement.
      if (c.track_stock) {
        DB.run('UPDATE variations SET stock = stock - ?, updated_at = ? WHERE id = ?', [c.qty, now, c.variation_id]);
        Sync.queue('stock', c.variation_id, 'decrement', { qty: c.qty, sale_id: saleId }, t.id);
      }
      return { name: c.name, sku: c.sku, qty: c.qty, unit_price: c.unit_price, line_total: c.unit_price * c.qty };
    });

    const saleRow = {
      receipt_no: receiptNo, order_no: orderNo, order_date: orderDate,
      subtotal: tot.itemsNet, vat_amount: tot.vat, total: tot.total,
      cash_received: cash, change_due: change, cashier: Config.cashierName(),
      vat_inclusive: t.vat_inclusive, vat_rate: tot.vatOn ? t.vat_rate : 0,
      service_charge: tot.service, service_charge_rate: tot.svcOn ? t.service_charge_rate : 0,
      created_at: now
    };
    // Queue the whole sale for the cloud (real-time figures across channels).
    Sync.queue('sale', saleId, 'create', { sale: Object.assign({ id: saleId, tenant_id: t.id }, saleRow), items }, t.id);
    DB.persistNow();

    closeModal();
    cart = [];
    renderCart(); renderPOS();
    updateSyncPill();

    // Success + receipt.
    const changeMsg = change > 0.001 ? ' · Change ' + money(change) : '';
    toast('Sale complete' + changeMsg, 'ok');
    openModal(`
      <header><h3>Sale complete</h3><button class="x" data-close>×</button></header>
      <div class="body center">
        <div class="kpi" style="margin-bottom:12px"><div class="v">${money(tot.total)}</div><div class="k">${esc(receiptNo)}</div></div>
        ${change > 0.001 ? `<p style="font-size:18px">Change due <b>${money(change)}</b></p>` : ''}
        <div class="toolbar" style="justify-content:center">
          <button class="btn brand" id="printReceiptBtn">🖨️ Print receipt</button>
          <button class="btn" data-close>New sale</button>
        </div>
      </div>`);
    $$('[data-close]', $('#modal')).forEach((b) => b.addEventListener('click', closeModal));
    $('#printReceiptBtn').addEventListener('click', () => Receipt.print(saleRow, items, t));
    if (Sync.configured()) Sync.run(false);
  }

  /* ---------------- Inventory ---------------- */
  let invFilter = '';
  function renderInventory() {
    const tid = Config.activeTenantId();
    const rows = DB.all(`
      SELECT v.*, p.name AS product_name, p.category, p.image, p.id AS pid,
             s.name AS supplier_name
      FROM variations v
      JOIN products p ON p.id = v.product_id
      LEFT JOIN suppliers s ON s.id = v.supplier_id
      WHERE v.tenant_id = ? ORDER BY p.name, v.price`, [tid]);

    const q = invFilter.toLowerCase();
    const filtered = rows.filter((r) => !q ||
      (r.product_name + ' ' + (r.name || '') + ' ' + (r.sku || '') + ' ' + (r.category || '')).toLowerCase().includes(q));

    // KPIs
    const skuCount = rows.length;
    const stockValue = rows.reduce((s, r) => s + (r.track_stock ? r.stock * r.cost : 0), 0);
    const retail = rows.reduce((s, r) => s + (r.track_stock ? r.stock * r.price : 0), 0);
    const low = rows.filter((r) => r.track_stock && r.stock <= r.low_stock_threshold).length;
    $('#invKpis').innerHTML = `
      ${kpi(skuCount, 'SKUs')}
      ${kpi(money(stockValue), 'Stock value (cost)')}
      ${kpi(money(retail), 'Retail value')}
      ${kpi(low, 'Low-stock items', low ? 'low' : '')}`;

    $('#invTable tbody').innerHTML = filtered.map((r) => {
      const lowb = r.track_stock && r.stock <= r.low_stock_threshold;
      return `<tr>
        <td>${r.image ? `<img class="thumb" src="${esc(r.image)}">` : '<div class="thumb"></div>'}</td>
        <td>${esc(r.product_name)}<div class="muted" style="font-size:12px">${esc(r.category || '')}</div></td>
        <td>${esc(r.name || '')}</td>
        <td>${esc(r.sku || '')}</td>
        <td>${money(r.price)}</td>
        <td>${money(r.cost)}</td>
        <td>${r.track_stock ? `<span class="badge ${lowb ? 'low' : 'ok'}">${r.stock}</span>` : '<span class="muted">∞</span>'}</td>
        <td>${esc(r.supplier_name || '—')}</td>
        <td>${r.active ? '<span class="badge ok">Active</span>' : '<span class="badge">Hidden</span>'}</td>
        <td><div class="row-actions">
          <button class="btn small" data-editprod="${r.pid}">Edit</button>
          <button class="btn small" data-restock="${r.id}">Restock</button>
        </div></td>
      </tr>`;
    }).join('') || '<tr><td colspan="10" class="muted center">No matching items.</td></tr>';
  }
  function kpi(v, k, cls) { return `<div class="kpi"><div class="v ${cls === 'low' ? '' : ''}">${v}</div><div class="k">${k}</div></div>`; }

  // Downscale an uploaded image to keep the local DB small, return dataURL.
  function fileToImage(file, maxSize) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        const img = new Image();
        img.onload = () => {
          const scale = Math.min(1, maxSize / Math.max(img.width, img.height));
          const w = Math.round(img.width * scale), h = Math.round(img.height * scale);
          const cv = document.createElement('canvas'); cv.width = w; cv.height = h;
          cv.getContext('2d').drawImage(img, 0, 0, w, h);
          resolve(cv.toDataURL('image/jpeg', 0.82));
        };
        img.onerror = reject; img.src = reader.result;
      };
      reader.onerror = reject; reader.readAsDataURL(file);
    });
  }

  // The category list for the active shop: the tenant's own headers, plus
  // sensible defaults, plus any categories already used by products.
  const DEFAULT_CATEGORIES = ['Food', 'Drinks', 'Desserts', 'Snacks', 'Services', 'General'];
  function tenantCategories(t) {
    let custom = [];
    try { custom = JSON.parse((t && t.categories) || '[]'); } catch (e) { custom = []; }
    const used = DB.all('SELECT DISTINCT category FROM products WHERE tenant_id = ? AND category IS NOT NULL', [t.id])
      .map((r) => r.category).filter(Boolean);
    const seen = new Set(); const out = [];
    [...custom, ...DEFAULT_CATEGORIES, ...used].forEach((c) => {
      const k = String(c).trim(); if (k && !seen.has(k.toLowerCase())) { seen.add(k.toLowerCase()); out.push(k); }
    });
    return out;
  }
  // Persist the tenant's category list (array of names) and sync it.
  function setTenantCategories(list) {
    const t = Config.activeTenant();
    const json = JSON.stringify(list);
    const now = DB.nowISO();
    DB.run('UPDATE tenants SET categories=?, updated_at=? WHERE id=?', [json, now, t.id]);
    Sync.queue('tenant', t.id, 'update', { id: t.id, categories: json, updated_at: now }, t.id);
    DB.persistNow();
  }
  function addTenantCategory(name) {
    const t = Config.activeTenant();
    let list = []; try { list = JSON.parse(t.categories || '[]'); } catch (e) {}
    if (!list.some((c) => String(c).toLowerCase() === name.toLowerCase())) { list.push(name); setTenantCategories(list); }
  }

  function productModal(pid, prefillBarcode) {
    const tid = Config.activeTenantId();
    const editing = !!pid;
    const p = editing ? DB.get('SELECT * FROM products WHERE id = ?', [pid])
                      : { id: '', name: '', category: 'General', color: '#334155', image: '', description: '', active: 1 };
    let vars = editing ? DB.all('SELECT * FROM variations WHERE product_id = ? ORDER BY price', [pid]) : [];
    if (!vars.length) vars = [{ id: '', name: 'Default', sku: '', barcode: prefillBarcode || '', price: 0, cost: 0, stock: 0, track_stock: 1, low_stock_threshold: 5, supplier_id: '', active: 1 }];
    const suppliers = DB.all('SELECT * FROM suppliers WHERE tenant_id = ? ORDER BY name', [tid]);
    let image = p.image || '';

    function varRow(v, i) {
      return `<div class="card" style="padding:10px" data-vrow="${i}">
        <div class="grid2">
          <div><label>Variation</label><input data-v="name" value="${esc(v.name || '')}"></div>
          <div><label>SKU</label><input data-v="sku" value="${esc(v.sku || '')}"></div>
          <div><label>Barcode</label><input data-v="barcode" value="${esc(v.barcode || '')}" placeholder="scan or type"></div>
          <div><label>Price</label><input data-v="price" type="number" step="0.01" value="${v.price}"></div>
          <div><label>Cost</label><input data-v="cost" type="number" step="0.01" value="${v.cost}"></div>
          <div><label>Stock</label><input data-v="stock" type="number" step="1" value="${v.stock}"></div>
          <div><label>Low-stock alert at</label><input data-v="low_stock_threshold" type="number" step="1" value="${v.low_stock_threshold}"></div>
          <div><label>Supplier</label><select data-v="supplier_id">
            <option value="">—</option>
            ${suppliers.map((s) => `<option value="${s.id}" ${s.id === v.supplier_id ? 'selected' : ''}>${esc(s.name)}</option>`).join('')}
          </select></div>
          <div><label>Discount</label><select data-v="discount_type">
            <option value="none" ${(!v.discount_type || v.discount_type === 'none') ? 'selected' : ''}>No discount</option>
            <option value="percent" ${v.discount_type === 'percent' ? 'selected' : ''}>% off</option>
            <option value="amount" ${v.discount_type === 'amount' ? 'selected' : ''}>Amount off</option>
          </select></div>
          <div><label>Discount value</label><input data-v="discount_value" type="number" step="0.01" min="0" value="${v.discount_value || 0}"></div>
          <div><label>Track stock</label><select data-v="track_stock">
            <option value="1" ${v.track_stock ? 'selected' : ''}>Yes</option>
            <option value="0" ${!v.track_stock ? 'selected' : ''}>No (service)</option>
          </select></div>
        </div>
        <input type="hidden" data-v="id" value="${esc(v.id || '')}">
        ${vars.length > 1 ? `<button class="btn danger small" data-delvar="${i}" style="margin-top:8px">Remove variation</button>` : ''}
      </div>`;
    }

    openModal(`
      <header><h3>${editing ? 'Edit' : 'New'} product</h3><button class="x" data-close>×</button></header>
      <div class="body">
        <div class="grid2">
          <div><label>Name</label><input id="pName" value="${esc(p.name)}"></div>
          <div><label>Category</label>
            <select id="pCat">
              ${(() => {
                const cats = tenantCategories(Config.activeTenant());
                const cur = p.category || 'General';
                if (cur && !cats.some((c) => c.toLowerCase() === cur.toLowerCase())) cats.unshift(cur);
                return cats.map((c) => `<option value="${esc(c)}" ${c === cur ? 'selected' : ''}>${esc(c)}</option>`).join('')
                  + '<option value="__new__">➕ Add new category…</option>';
              })()}
            </select>
          </div>
        </div>
        <label>Description</label><input id="pDesc" value="${esc(p.description || '')}">
        <div class="grid2">
          <div><label>Tile colour</label><input id="pColor" type="color" value="${esc(p.color || '#334155')}"></div>
          <div><label>Visible on till</label><select id="pActive">
            <option value="1" ${p.active ? 'selected' : ''}>Yes</option><option value="0" ${!p.active ? 'selected' : ''}>No</option>
          </select></div>
        </div>
        <label>Product photo</label>
        <div class="toolbar">
          <img class="thumb" id="pImgPrev" src="${esc(image)}" style="${image ? '' : 'display:none'}">
          <input type="file" id="pImg" accept="image/*">
          ${image ? '<button class="btn small" id="pImgClear">Remove</button>' : ''}
        </div>
        <div class="section-title" style="margin-top:14px"><h3 style="margin:0">Variations & SKUs</h3>
          <button class="btn small" id="addVarBtn">+ Variation</button></div>
        <div id="varList">${vars.map(varRow).join('')}</div>
      </div>
      <div class="foot">
        ${editing ? '<button class="btn danger" id="delProdBtn" style="margin-right:auto">Delete</button>' : ''}
        <button class="btn ghost" data-close>Cancel</button>
        <button class="btn brand" id="saveProdBtn">Save</button>
      </div>`, true);

    const m = $('#modal');
    $$('[data-close]', m).forEach((b) => b.addEventListener('click', closeModal));

    $('#pImg', m).addEventListener('change', async (e) => {
      const f = e.target.files[0]; if (!f) return;
      image = await fileToImage(f, 512);
      const prev = $('#pImgPrev', m); prev.src = image; prev.style.display = '';
    });
    if ($('#pImgClear', m)) $('#pImgClear', m).addEventListener('click', () => {
      image = ''; $('#pImgPrev', m).style.display = 'none';
    });

    // "Add new category…" — prompt, insert as a selected option, and (best
    // effort) add it to the tenant's saved category list so it persists.
    let prevCat = $('#pCat', m).value;
    $('#pCat', m).addEventListener('change', (e) => {
      const sel = e.target;
      if (sel.value !== '__new__') { prevCat = sel.value; return; }
      const name = (prompt('New category name') || '').trim();
      if (!name) { sel.value = prevCat; return; }
      if (!Array.from(sel.options).some((o) => o.value.toLowerCase() === name.toLowerCase())) {
        const opt = document.createElement('option');
        opt.value = name; opt.textContent = name;
        sel.insertBefore(opt, sel.querySelector('option[value="__new__"]'));
      }
      sel.value = name; prevCat = name;
      addTenantCategory(name);
    });

    function bindVarDeletes() {
      $$('[data-delvar]', m).forEach((b) => b.addEventListener('click', () => {
        vars = collectVars(); vars.splice(parseInt(b.dataset.delvar, 10), 1);
        $('#varList', m).innerHTML = vars.map(varRow).join(''); bindVarDeletes();
      }));
    }
    bindVarDeletes();
    $('#addVarBtn', m).addEventListener('click', () => {
      vars = collectVars();
      vars.push({ id: '', name: 'Variation', sku: '', price: 0, cost: 0, stock: 0, track_stock: 1, low_stock_threshold: 5, supplier_id: '', active: 1 });
      $('#varList', m).innerHTML = vars.map(varRow).join(''); bindVarDeletes();
    });

    function collectVars() {
      return $$('[data-vrow]', m).map((row) => {
        const g = (k) => { const el = row.querySelector(`[data-v="${k}"]`); return el ? el.value : ''; };
        return {
          id: g('id'), name: g('name') || 'Default', sku: g('sku'), barcode: g('barcode').trim(),
          price: parseFloat(g('price')) || 0, cost: parseFloat(g('cost')) || 0,
          stock: parseFloat(g('stock')) || 0, track_stock: g('track_stock') === '1' ? 1 : 0,
          low_stock_threshold: parseFloat(g('low_stock_threshold')) || 0,
          supplier_id: g('supplier_id') || null,
          discount_type: g('discount_type') || 'none', discount_value: parseFloat(g('discount_value')) || 0,
          active: 1
        };
      });
    }

    if ($('#delProdBtn', m)) $('#delProdBtn', m).addEventListener('click', () => {
      if (!confirm('Delete this product and its variations?')) return;
      DB.run('UPDATE products SET active = 0, updated_at = ? WHERE id = ?', [DB.nowISO(), pid]);
      DB.run('UPDATE variations SET active = 0, updated_at = ? WHERE product_id = ?', [DB.nowISO(), pid]);
      Sync.queue('product', pid, 'delete', { id: pid }, tid);
      DB.persistNow(); closeModal(); renderInventory(); renderPOS(); toast('Product removed');
    });

    $('#saveProdBtn', m).addEventListener('click', () => {
      const name = $('#pName', m).value.trim();
      if (!name) { toast('Name is required', 'err'); return; }
      const now = DB.nowISO();
      const collected = collectVars();
      let productId = pid;
      const payload = {
        name, category: (($('#pCat', m).value || '').trim() === '__new__' ? '' : $('#pCat', m).value.trim()) || 'General',
        description: $('#pDesc', m).value.trim(), color: $('#pColor', m).value,
        image, active: parseInt($('#pActive', m).value, 10)
      };
      if (editing) {
        DB.run(`UPDATE products SET name=?,category=?,description=?,color=?,image=?,active=?,updated_at=? WHERE id=?`,
          [payload.name, payload.category, payload.description, payload.color, payload.image, payload.active, now, pid]);
      } else {
        productId = DB.uid('prd');
        DB.run(`INSERT INTO products(id,tenant_id,name,category,description,color,image,active,sort,updated_at,created_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
          [productId, tid, payload.name, payload.category, payload.description, payload.color, payload.image, payload.active, 0, now, now]);
      }
      // Reconcile variations.
      const keptIds = [];
      collected.forEach((v) => {
        if (v.id) {
          DB.run(`UPDATE variations SET name=?,sku=?,barcode=?,price=?,cost=?,stock=?,track_stock=?,low_stock_threshold=?,supplier_id=?,discount_type=?,discount_value=?,active=1,updated_at=? WHERE id=?`,
            [v.name, v.sku, v.barcode, v.price, v.cost, v.stock, v.track_stock, v.low_stock_threshold, v.supplier_id, v.discount_type, v.discount_value, now, v.id]);
          keptIds.push(v.id);
        } else {
          const vid = DB.uid('var');
          DB.run(`INSERT INTO variations(id,product_id,tenant_id,name,sku,barcode,price,cost,stock,track_stock,low_stock_threshold,supplier_id,discount_type,discount_value,active,updated_at,created_at)
                  VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
            [vid, productId, tid, v.name, v.sku, v.barcode, v.price, v.cost, v.stock, v.track_stock, v.low_stock_threshold, v.supplier_id, v.discount_type, v.discount_value, 1, now, now]);
          keptIds.push(vid);
        }
      });
      // Deactivate removed variations.
      DB.all('SELECT id FROM variations WHERE product_id = ?', [productId]).forEach((r) => {
        if (!keptIds.includes(r.id)) DB.run('UPDATE variations SET active=0, updated_at=? WHERE id=?', [now, r.id]);
      });

      Sync.queue('product', productId, editing ? 'update' : 'create',
        { product: Object.assign({ id: productId, tenant_id: tid }, payload),
          variations: DB.all('SELECT * FROM variations WHERE product_id = ?', [productId]) }, tid);
      DB.persistNow();
      closeModal(); renderInventory(); renderPOS();
      toast(editing ? 'Product updated' : 'Product added', 'ok');
    });
  }

  function restockModal(vid) {
    const v = DB.get(`SELECT v.*, p.name AS pname FROM variations v JOIN products p ON p.id=v.product_id WHERE v.id=?`, [vid]);
    openModal(`
      <header><h3>Restock · ${esc(v.pname)} ${esc(v.name && v.name !== 'Default' ? v.name : '')}</h3><button class="x" data-close>×</button></header>
      <div class="body">
        <p class="muted">Current stock: <b>${v.stock}</b> · SKU ${esc(v.sku || '—')}</p>
        <label>Add quantity received</label><input id="rQty" type="number" step="1" value="0">
        <label>Set new stock level (optional, overrides add)</label><input id="rSet" type="number" step="1" placeholder="leave blank">
      </div>
      <div class="foot"><button class="btn ghost" data-close>Cancel</button><button class="btn brand" id="rSave">Save</button></div>`);
    const m = $('#modal');
    $$('[data-close]', m).forEach((b) => b.addEventListener('click', closeModal));
    $('#rSave', m).addEventListener('click', () => {
      const setVal = $('#rSet', m).value.trim();
      const now = DB.nowISO();
      let newStock;
      if (setVal !== '') newStock = parseFloat(setVal) || 0;
      else newStock = v.stock + (parseFloat($('#rQty', m).value) || 0);
      DB.run('UPDATE variations SET stock=?, updated_at=? WHERE id=?', [newStock, now, vid]);
      Sync.queue('stock', vid, 'set', { stock: newStock }, v.tenant_id);
      DB.persistNow(); closeModal(); renderInventory(); renderPOS(); toast('Stock updated', 'ok');
    });
  }

  /* ---------------- Suppliers ---------------- */
  let supFilter = '';
  function renderSuppliers() {
    const tid = Config.activeTenantId();
    const rows = DB.all('SELECT * FROM suppliers WHERE tenant_id = ? ORDER BY name', [tid]);
    const q = supFilter.toLowerCase();
    const filtered = rows.filter((r) => !q || (r.name + ' ' + (r.contact || '') + ' ' + (r.email || '')).toLowerCase().includes(q));
    $('#supTable tbody').innerHTML = filtered.map((r) => {
      const items = DB.get('SELECT COUNT(*) AS n FROM variations WHERE supplier_id = ? AND active=1', [r.id]);
      return `<tr>
        <td>${esc(r.name)}</td><td>${esc(r.contact || '')}</td><td>${esc(r.phone || '')}</td>
        <td>${esc(r.email || '')}</td><td>${items ? items.n : 0}</td>
        <td><button class="btn small" data-editsup="${r.id}">Edit</button></td>
      </tr>`;
    }).join('') || '<tr><td colspan="6" class="muted center">No suppliers yet.</td></tr>';
  }
  function supplierModal(sid) {
    const editing = !!sid;
    const s = editing ? DB.get('SELECT * FROM suppliers WHERE id = ?', [sid]) : {};
    openModal(`
      <header><h3>${editing ? 'Edit' : 'New'} supplier</h3><button class="x" data-close>×</button></header>
      <div class="body">
        <label>Name</label><input id="sName" value="${esc(s.name || '')}">
        <div class="grid2">
          <div><label>Contact person</label><input id="sContact" value="${esc(s.contact || '')}"></div>
          <div><label>Phone</label><input id="sPhone" value="${esc(s.phone || '')}"></div>
        </div>
        <label>Email</label><input id="sEmail" value="${esc(s.email || '')}">
        <label>Address</label><input id="sAddr" value="${esc(s.address || '')}">
      </div>
      <div class="foot"><button class="btn ghost" data-close>Cancel</button><button class="btn brand" id="sSave">Save</button></div>`);
    const m = $('#modal');
    $$('[data-close]', m).forEach((b) => b.addEventListener('click', closeModal));
    $('#sSave', m).addEventListener('click', () => {
      const name = $('#sName', m).value.trim();
      if (!name) { toast('Name required', 'err'); return; }
      const now = DB.nowISO(); const tid = Config.activeTenantId();
      const data = [name, $('#sContact', m).value.trim(), $('#sPhone', m).value.trim(), $('#sEmail', m).value.trim(), $('#sAddr', m).value.trim()];
      if (editing) DB.run('UPDATE suppliers SET name=?,contact=?,phone=?,email=?,address=?,updated_at=? WHERE id=?', [...data, now, sid]);
      else DB.run('INSERT INTO suppliers(id,tenant_id,name,contact,phone,email,address,updated_at,created_at) VALUES(?,?,?,?,?,?,?,?,?)',
        [DB.uid('sup'), tid, ...data, now, now]);
      DB.persistNow(); closeModal(); renderSuppliers(); toast('Saved', 'ok');
    });
  }

  /* ---------------- Reports ---------------- */
  let repShowFigures = false; // sales/income hidden by default each visit
  let repFrom = '', repTo = '', repSearch = ''; // report filters
  function renderReports() {
    const tid = Config.activeTenantId();
    const today = new Date(); today.setHours(0, 0, 0, 0);
    const allSales = DB.all('SELECT * FROM sales WHERE tenant_id = ? ORDER BY created_at DESC', [tid]);
    const isVoid = (s) => (s.status || 'completed') === 'voided';
    const pending = DB.get('SELECT COUNT(*) AS n FROM sales WHERE tenant_id=? AND synced=0', [tid]);

    // Reflect current filter values into the inputs.
    $('#repFrom').value = repFrom; $('#repTo').value = repTo; $('#repSearch').value = repSearch;
    const from = repFrom ? new Date(repFrom + 'T00:00:00') : null;
    const to = repTo ? new Date(repTo + 'T23:59:59.999') : null;
    const q = repSearch.trim().toLowerCase();
    const inFilter = (s) => {
      const d = new Date(s.created_at);
      if (from && d < from) return false;
      if (to && d > to) return false;
      if (q) {
        const hay = (s.receipt_no || '').toLowerCase() + ' ' + (s.created_at || '').slice(0, 10) +
          ' ' + (s.order_no != null ? 'order #' + s.order_no : '');
        if (!hay.includes(q)) return false;
      }
      return true;
    };
    const filterActive = !!(from || to || q);
    const filtered = allSales.filter(inFilter);
    const display = filterActive ? filtered : allSales.slice(0, 100);

    // KPIs reflect the selected range when a filter is active, else today.
    const kpiSet = (filterActive ? filtered : allSales.filter((s) => new Date(s.created_at) >= today))
      .filter((s) => !isVoid(s));
    const lbl = filterActive ? 'Selected' : 'Today';

    // Money figures are masked until the manager explicitly reveals them.
    $('#repShowFigures').checked = repShowFigures;
    $('#repPrivacyHint').textContent = repShowFigures ? 'Figures are visible.' : 'Figures are hidden by default for privacy.';
    const cash = (v) => repShowFigures ? money(v) : '••••••';

    // Report Analytics is a tier feature: the button stays inert until an admin
    // enables it for this shop.
    const tnt = Config.activeTenant() || {};
    const analyticsOn = tnt.analytics_enabled === 1;
    const ab = $('#repAnalyticsBtn');
    if (ab) { ab.disabled = !analyticsOn; ab.classList.toggle('brand', analyticsOn); ab.classList.toggle('ghost', !analyticsOn);
      ab.textContent = analyticsOn ? '📈 Report Analytics' : '📈 Report Analytics (off)'; }

    $('#repKpis').innerHTML =
      kpi(cash(kpiSet.reduce((a, r) => a + r.total, 0)), lbl + ' sales') +
      kpi(kpiSet.length, 'Transactions (' + lbl.toLowerCase() + ')') +
      kpi(cash(kpiSet.reduce((a, r) => a + r.vat_amount, 0)), 'VAT (' + lbl.toLowerCase() + ')') +
      kpi(pending ? pending.n : 0, 'Unsynced sales');

    const canEdit = canManage();
    $('#salesTable tbody').innerHTML = display.map((s) => {
      const voided = isVoid(s);
      const actions = voided
        ? `<button class="btn small" data-reprint="${s.id}">Receipt</button>`
        : `<button class="btn small" data-reprint="${s.id}">Receipt</button>` +
          (canEdit ? ` <button class="btn small" data-editsale="${s.id}">Edit</button>` +
                     ` <button class="btn small danger" data-voidsale="${s.id}">Void</button>` : '');
      return `<tr${voided ? ' style="opacity:.55"' : ''}>
        <td>${esc(s.receipt_no)}${voided ? ' <span class="badge">Voided</span>' : ''}</td>
        <td>${new Date(s.created_at).toLocaleString()}</td>
        <td>${s.item_count}</td><td>${cash(s.total)}</td><td>${cash(s.cash_received)}</td>
        <td>${s.synced ? '<span class="badge ok">Synced</span>' : '<span class="badge">Pending</span>'}</td>
        <td><div class="row-actions">${actions}</div></td>
      </tr>`;
    }).join('') || `<tr><td colspan="7" class="muted center">${filterActive ? 'No sales match the filter.' : 'No sales yet.'}</td></tr>`;

    const low = DB.all(`
      SELECT v.*, p.name AS pname, s.name AS supplier_name FROM variations v
      JOIN products p ON p.id=v.product_id LEFT JOIN suppliers s ON s.id=v.supplier_id
      WHERE v.tenant_id=? AND v.active=1 AND v.track_stock=1 AND v.stock <= v.low_stock_threshold
      ORDER BY v.stock`, [tid]);
    $('#lowTable tbody').innerHTML = low.map((r) => `<tr>
      <td>${esc(r.pname)} ${esc(r.name && r.name !== 'Default' ? '· ' + r.name : '')}</td>
      <td>${esc(r.sku || '')}</td><td><span class="badge low">${r.stock}</span></td>
      <td>${r.low_stock_threshold}</td><td>${esc(r.supplier_name || '—')}</td>
    </tr>`).join('') || '<tr><td colspan="5" class="muted center">All stock levels healthy. 🎉</td></tr>';
  }
  function reprint(saleId) {
    const s = DB.get('SELECT * FROM sales WHERE id = ?', [saleId]);
    const items = DB.all('SELECT * FROM sale_items WHERE sale_id = ?', [saleId]);
    const t = DB.get('SELECT * FROM tenants WHERE id = ?', [s.tenant_id]);
    Receipt.print(s, items, t);
  }

  // Report Analytics (tier feature): a compact insights panel — last 7 days
  // trend, top products and payment mix. Only reachable when admin-enabled.
  function openAnalytics() {
    const tid = Config.activeTenantId();
    const since = new Date(Date.now() - 29 * 864e5); // last 30 days
    const sales = DB.all('SELECT * FROM sales WHERE tenant_id=? ORDER BY created_at DESC', [tid])
      .filter((s) => (s.status || 'completed') !== 'voided' && new Date(s.created_at) >= since);
    const items = DB.all(`SELECT si.* FROM sale_items si JOIN sales s ON s.id=si.sale_id
      WHERE si.tenant_id=? AND (s.status IS NULL OR s.status='completed') AND s.created_at >= ?`, [tid, since.toISOString()]);

    const total = sales.reduce((a, s) => a + s.total, 0);
    const count = sales.length;
    const avg = count ? total / count : 0;

    // Daily totals for the last 7 days (simple inline bars).
    const days = [];
    for (let i = 6; i >= 0; i--) {
      const d = new Date(); d.setHours(0, 0, 0, 0); d.setDate(d.getDate() - i);
      const key = Config.todayKey(d);
      const dayTotal = sales.filter((s) => (s.created_at || '').slice(0, 10) === key).reduce((a, s) => a + s.total, 0);
      days.push({ key, label: d.toLocaleDateString(undefined, { weekday: 'short' }), total: dayTotal });
    }
    const maxDay = Math.max(1, ...days.map((d) => d.total));

    // Top products by revenue.
    const byProduct = {};
    items.forEach((it) => {
      const k = it.name || 'Item';
      byProduct[k] = byProduct[k] || { qty: 0, revenue: 0 };
      byProduct[k].qty += Number(it.qty) || 0;
      byProduct[k].revenue += Number(it.line_total) || 0;
    });
    const top = Object.entries(byProduct).sort((a, b) => b[1].revenue - a[1].revenue).slice(0, 8);

    openModal(`
      <header><h3>📈 Report Analytics · last 30 days</h3><button class="x" data-close>×</button></header>
      <div class="body">
        <div class="kpis">
          ${kpi(money(total), 'Revenue (30d)')}
          ${kpi(count, 'Transactions')}
          ${kpi(money(avg), 'Average sale')}
        </div>
        <h3 style="margin:14px 0 6px">Last 7 days</h3>
        <div class="bars">
          ${days.map((d) => `<div class="bar"><span class="barfill" style="height:${Math.round((d.total / maxDay) * 100)}%"></span>
            <span class="barlbl">${d.label}</span></div>`).join('')}
        </div>
        <h3 style="margin:16px 0 6px">Top products</h3>
        <div class="table-wrap"><table class="data"><thead><tr><th>Product</th><th>Qty</th><th>Revenue</th></tr></thead>
          <tbody>${top.map(([n, v]) => `<tr><td>${esc(n)}</td><td>${v.qty}</td><td>${money(v.revenue)}</td></tr>`).join('')
            || '<tr><td colspan="3" class="muted center">No sales in the last 30 days.</td></tr>'}</tbody></table></div>
      </div>
      <div class="foot"><button class="btn ghost" data-close>Close</button></div>`, true);
    $$('[data-close]', $('#modal')).forEach((b) => b.addEventListener('click', closeModal));
  }

  // Void a sale: mark it voided, return its items to stock, and sync. Kept in
  // the list (struck through) as an audit trail; excluded from all figures.
  function voidSale(saleId, silent) {
    const s = DB.get('SELECT * FROM sales WHERE id = ?', [saleId]);
    if (!s || (s.status || 'completed') === 'voided') return s;
    if (!silent && !confirm('Void this order? Its items go back into stock and it is removed from sales totals.')) return null;
    const now = DB.nowISO();
    // Return stock for tracked items.
    DB.all('SELECT * FROM sale_items WHERE sale_id = ?', [saleId]).forEach((it) => {
      if (!it.variation_id) return;
      const v = DB.get('SELECT stock, track_stock FROM variations WHERE id = ?', [it.variation_id]);
      if (v && v.track_stock) {
        const ns = Number(v.stock) + Number(it.qty);
        DB.run('UPDATE variations SET stock=?, updated_at=? WHERE id=?', [ns, now, it.variation_id]);
        Sync.queue('stock', it.variation_id, 'set', { stock: ns }, s.tenant_id);
      }
    });
    DB.run("UPDATE sales SET status='voided' WHERE id=?", [saleId]);
    // Push the voided status up (upsert of the sale record with status voided).
    Sync.queue('sale', saleId, 'update',
      { sale: { id: saleId, tenant_id: s.tenant_id, status: 'voided' } }, s.tenant_id);
    DB.persistNow();
    if (!silent) { renderReports(); renderPOS(); updateSyncPill(); toast('Order voided', 'ok'); }
    return s;
  }

  // Edit a sale: void the original and reload its items into the cart so the
  // cashier can correct it and charge again.
  function editSale(saleId) {
    const s = DB.get('SELECT * FROM sales WHERE id = ?', [saleId]);
    if (!s || (s.status || 'completed') === 'voided') return;
    if (!confirm('Edit this order? It will be voided and its items loaded back into a new sale to re-ring.')) return;
    const items = DB.all('SELECT * FROM sale_items WHERE sale_id = ?', [saleId]);
    voidSale(saleId, true); // silent void + restock
    // Rebuild the cart from the sale's items using current variation data.
    cart = [];
    items.forEach((it) => {
      const v = it.variation_id ? DB.get('SELECT * FROM variations WHERE id = ?', [it.variation_id]) : null;
      cart.push({
        variation_id: it.variation_id, product_id: it.product_id, name: it.name, sku: it.sku,
        unit_price: it.unit_price, qty: it.qty,
        track_stock: v ? !!v.track_stock : false, stock: v ? v.stock : 0
      });
    });
    DB.persistNow();
    renderReports(); renderCart(); renderPOS(); updateSyncPill();
    switchView('pos');
    toast('Order loaded for editing — adjust and charge again', 'ok');
  }

  /* ---------------- Admin (tenant management) ---------------- */
  let tenantFilter = '';
  function isAdminUnlocked() { return sessionStorage.getItem('admin_ok') === '1'; }
  function renderAdmin() {
    const unlocked = isAdminUnlocked();
    $('#adminLock').style.display = unlocked ? 'none' : '';
    $('#adminPanel').style.display = unlocked ? '' : 'none';
    if (!unlocked) return;
    // Cloud + admin details live here, behind the admin password.
    // Show the effective cloud URL: the admin's override, or the embedded default.
    const storedApi = DB.getSetting('api_base');
    $('#setApiBase').value = (storedApi === null || storedApi === undefined) ? Config.DEFAULT_API_BASE : storedApi;
    updateSyncPill();
    const q = tenantFilter.toLowerCase();
    const rows = DB.all('SELECT * FROM tenants ORDER BY name').filter((t) =>
      !q || (t.name + ' ' + (t.tin || '')).toLowerCase().includes(q));
    $('#tenantTable tbody').innerHTML = rows.map((t) => {
      const pc = DB.get('SELECT COUNT(*) AS n FROM products WHERE tenant_id=? AND active=1', [t.id]);
      const statusBadge = t.status === 'suspended' ? '<span class="badge suspended">Suspended</span>' : '<span class="badge ok">Active</span>';
      return `<tr>
        <td>${esc(t.name)}<div class="muted" style="font-size:12px">${esc(t.address || '')}</div></td>
        <td>${esc(t.tin || '—')}</td><td>${esc(t.phone || '')}</td><td>${pc ? pc.n : 0}</td>
        <td>${statusBadge}</td>
        <td><div class="row-actions">
          <button class="btn small" data-edittenant="${t.id}">Edit</button>
          <button class="btn small" data-stafftenant="${t.id}">Staff</button>
          <button class="btn small" data-usetenant="${t.id}">Open</button>
          <button class="btn small ${t.status === 'suspended' ? 'brand' : 'danger'}" data-toggletenant="${t.id}">${t.status === 'suspended' ? 'Activate' : 'Suspend'}</button>
        </div></td>
      </tr>`;
    }).join('');
  }
  function tenantModal(tid) {
    const editing = !!tid;
    const t = editing ? DB.get('SELECT * FROM tenants WHERE id = ?', [tid])
      : { currency: 'GYD', vat_rate: 15, vat_inclusive: 1, status: 'active' };
    const curOpts = Object.keys(Config.CURRENCY_SYMBOLS).map((c) =>
      `<option value="${c}" ${t.currency === c ? 'selected' : ''}>${c}</option>`).join('');
    openModal(`
      <header><h3>${editing ? 'Edit' : 'New'} tenant</h3><button class="x" data-close>×</button></header>
      <div class="body">
        <label>Business name</label><input id="tName" value="${esc(t.name || '')}">
        <div class="grid2">
          <div><label>TIN number</label><input id="tTin" value="${esc(t.tin || '')}"></div>
          <div><label>Receipt prefix / slug</label><input id="tSlug" value="${esc(t.slug || '')}"></div>
          <div><label>Phone</label><input id="tPhone" value="${esc(t.phone || '')}"></div>
          <div><label>Email</label><input id="tEmail" value="${esc(t.email || '')}"></div>
        </div>
        <label>Location / address</label><input id="tAddr" value="${esc(t.address || '')}">
        <div class="grid2">
          <div><label>Currency</label><select id="tCur">${curOpts}</select></div>
          <div><label>VAT rate (%)</label><input id="tVat" type="number" step="0.1" value="${t.vat_rate}"></div>
          <div><label>VAT pricing</label><select id="tVatInc">
            <option value="1" ${t.vat_inclusive ? 'selected' : ''}>Inclusive (price contains VAT)</option>
            <option value="0" ${!t.vat_inclusive ? 'selected' : ''}>Exclusive (VAT added)</option>
          </select></div>
          <div><label>Status</label><select id="tStatus">
            <option value="active" ${t.status !== 'suspended' ? 'selected' : ''}>Active</option>
            <option value="suspended" ${t.status === 'suspended' ? 'selected' : ''}>Suspended</option>
          </select></div>
        </div>
        <label>Receipt footer message</label><input id="tFooter" value="${esc(t.receipt_footer || '')}">
        <label class="switch" style="margin-top:10px"><input type="checkbox" id="tAnalytics" ${t.analytics_enabled === 1 ? 'checked' : ''}> Enable Report Analytics (paid tier)</label>
      </div>
      <div class="foot"><button class="btn ghost" data-close>Cancel</button><button class="btn brand" id="tSave">Save</button></div>`, true);
    const m = $('#modal');
    $$('[data-close]', m).forEach((b) => b.addEventListener('click', closeModal));
    $('#tSave', m).addEventListener('click', async () => {
      const name = $('#tName', m).value.trim();
      if (!name) { toast('Business name required', 'err'); return; }
      const now = DB.nowISO();
      const vals = {
        name, tin: $('#tTin', m).value.trim(), slug: $('#tSlug', m).value.trim(),
        phone: $('#tPhone', m).value.trim(), email: $('#tEmail', m).value.trim(),
        address: $('#tAddr', m).value.trim(), currency: $('#tCur', m).value,
        vat_rate: parseFloat($('#tVat', m).value) || 0, vat_inclusive: parseInt($('#tVatInc', m).value, 10),
        status: $('#tStatus', m).value, receipt_footer: $('#tFooter', m).value.trim(),
        analytics_enabled: $('#tAnalytics', m).checked ? 1 : 0
      };
      let id = tid;
      if (editing) {
        DB.run(`UPDATE tenants SET name=?,tin=?,slug=?,phone=?,email=?,address=?,currency=?,vat_rate=?,vat_inclusive=?,status=?,receipt_footer=?,analytics_enabled=?,updated_at=? WHERE id=?`,
          [vals.name, vals.tin, vals.slug, vals.phone, vals.email, vals.address, vals.currency, vals.vat_rate, vals.vat_inclusive, vals.status, vals.receipt_footer, vals.analytics_enabled, now, tid]);
      } else {
        id = DB.uid('ten');
        DB.run(`INSERT INTO tenants(id,name,tin,slug,phone,email,address,currency,vat_rate,vat_inclusive,status,receipt_footer,analytics_enabled,updated_at,created_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
          [id, vals.name, vals.tin, vals.slug, vals.phone, vals.email, vals.address, vals.currency, vals.vat_rate, vals.vat_inclusive, vals.status, vals.receipt_footer, vals.analytics_enabled, now, now]);
        // Give a brand-new shop a default manager login (change the PIN after).
        await createStaff(id, { name: 'Manager', username: 'manager', pin: '1234', role: 'manager' });
      }
      Sync.queue('tenant', id, editing ? 'update' : 'create', Object.assign({ id }, vals), id);
      DB.persistNow();
      closeModal(); updateTopbar(); renderAdmin();
      toast(editing ? 'Tenant updated' : 'Tenant created — default login manager / 1234', 'ok');
    });
  }

  /* ---------------- Authentication & sessions ---------------- */

  // Tabs a cashier may not open. Managers/admins see everything.
  const MANAGER_TABS = ['inventory', 'suppliers', 'settings'];

  function activeTenants() {
    return DB.all("SELECT * FROM tenants WHERE status != 'suspended' ORDER BY name");
  }

  function populateLoginTenants() {
    // Prefill this device's last shop name for convenience (no dropdown of all
    // shops, so other tenants' names are not exposed).
    const last = DB.getSetting('active_tenant_id');
    const t = last ? DB.get('SELECT name FROM tenants WHERE id = ?', [last]) : null;
    const field = $('#loginShop');
    if (field && t && !field.value) field.value = t.name;
  }

  // Resolve a typed shop name to an active tenant (case/space-insensitive).
  function findTenantByName(name) {
    const norm = String(name || '').trim().toLowerCase();
    if (!norm) return null;
    return activeTenants().find((t) =>
      (t.name || '').trim().toLowerCase() === norm ||
      (t.slug || '').trim().toLowerCase() === norm) || null;
  }

  function updateTopbar() {
    const s = Config.currentSession();
    const t = Config.activeTenant();
    $('#tenantName').textContent = t ? t.name : '—';
    $('#userName').textContent = s ? (s.name + ' · ' + (s.role || 'cashier')) : '—';
    updateBrand();
  }
  function updateBrand() {
    const t = Config.activeTenant();
    $('#brandLogo').src = (t && t.logo) ? t.logo : './icons/icon.svg';
    $('#brandName').textContent = t ? t.name : 'Totals POS';
  }

  function canManage() {
    const r = Config.currentRole();
    return r === 'manager' || r === 'admin';
  }

  // Save a downscaled logo for the active shop (managers only).
  async function saveLogo(file) {
    if (!canManage()) { toast('Managers only', 'err'); return; }
    const t = Config.activeTenant();
    const dataUrl = file ? await fileToImage(file, 256) : '';
    const now = DB.nowISO();
    DB.run('UPDATE tenants SET logo=?, updated_at=? WHERE id=?', [dataUrl, now, t.id]);
    Sync.queue('tenant', t.id, 'update', { id: t.id, logo: dataUrl, updated_at: now }, t.id);
    DB.persistNow();
    updateBrand();
    if ($('#logoPrev')) $('#logoPrev').src = dataUrl || './icons/icon.svg';
    toast(dataUrl ? 'Logo updated' : 'Logo removed', 'ok');
  }

  // Hide manager-only tabs for cashiers; keep the current view valid.
  function applyRoleGating() {
    const role = Config.currentRole();
    const isManager = role === 'manager' || role === 'admin';
    MANAGER_TABS.forEach((v) => {
      const tab = document.querySelector('.tab[data-view="' + v + '"]');
      if (tab) tab.classList.toggle('hidden-role', !isManager);
    });
    // Admin tab stays visible for everyone (still gated by the device PIN).
    if (!isManager) {
      const active = document.querySelector('.tab.active');
      if (active && MANAGER_TABS.includes(active.dataset.view)) switchView('pos');
    }
    // The per-shop Staff card is manager-only.
    const staffCard = $('#staffCard'); if (staffCard) staffCard.style.display = isManager ? '' : 'none';
  }

  function showLogin() {
    populateLoginTenants();
    $('#loginErr').textContent = '';
    $('#loginPin').value = '';
    $('#loginBack').classList.add('open');
    setTimeout(() => $('#loginUser').focus(), 50);
    // Proactively pull shops/staff so a fresh device knows about them by the
    // time someone signs in.
    if (Sync.configured() && navigator.onLine) Sync.run(true);
  }
  function hideLogin() { $('#loginBack').classList.remove('open'); }

  async function attemptLogin() {
    const shop = $('#loginShop').value;
    const user = $('#loginUser').value.trim().toLowerCase();
    const pin = $('#loginPin').value;
    const err = $('#loginErr');
    const btn = $('#loginBtn');
    if (!shop.trim()) { err.textContent = 'Enter your shop name.'; return; }
    if (!user || !pin) { err.textContent = 'Enter your username and PIN.'; return; }

    let tenant = findTenantByName(shop);
    // First login on a fresh device: the shop hasn't synced down yet — fetch
    // from the cloud on demand, then look again.
    if (!tenant && Sync.configured() && navigator.onLine) {
      err.style.color = 'var(--muted)'; err.textContent = 'Fetching your shop from the cloud…';
      btn.disabled = true;
      try { await Sync.run(true); } catch (e) {}
      btn.disabled = false; err.style.color = '';
      tenant = findTenantByName(shop);
    }
    if (!tenant) {
      err.style.color = '';
      err.textContent = Sync.configured()
        ? 'Shop not found. Check the exact name, and make sure this device is online.'
        : 'Shop not found on this device, and cloud sync is off.';
      return;
    }
    const staff = DB.get('SELECT * FROM staff WHERE tenant_id = ? AND lower(username) = ? AND active = 1', [tenant.id, user]);
    if (!staff) { err.textContent = 'Unknown user for this shop.'; return; }
    const hash = await Config.hashPin(pin, staff.salt);
    if (hash !== staff.pin_hash) { err.textContent = 'Incorrect PIN.'; return; }
    signInAs({ tenant_id: tenant.id, staff_id: staff.id, name: staff.name, role: staff.role });
  }

  function signInAs(session) {
    // A new sign-in never inherits a previous admin unlock; the Admin tab must
    // be unlocked again with the device PIN (unless this is an admin override).
    if (session.admin) sessionStorage.setItem('admin_ok', '1');
    else sessionStorage.removeItem('admin_ok');
    Config.setSession(session);
    Config.setActiveTenant(session.tenant_id);
    DB.persistNow();
    hideLogin();
    cart = [];
    applyRoleGating();
    updateTopbar();
    renderPOS(); renderCart();
    switchView('pos');
    toast('Signed in — ' + session.name, 'ok');
  }

  function signOut() {
    // Signing out of any profile revokes admin access until re-authenticated.
    sessionStorage.removeItem('admin_ok');
    Config.setSession(null);
    cart = [];
    updateTopbar();
    showLogin();
  }

  // Returns true if a stored session is still valid (tenant active, staff ok).
  function restoreSession() {
    const s = Config.currentSession();
    if (!s) return false;
    const t = DB.get("SELECT * FROM tenants WHERE id = ? AND status != 'suspended'", [s.tenant_id]);
    if (!t) return false;
    if (s.admin) { Config.setActiveTenant(s.tenant_id); return true; } // device-admin override
    const staff = DB.get('SELECT * FROM staff WHERE id = ? AND active = 1', [s.staff_id]);
    if (!staff) return false;
    Config.setActiveTenant(s.tenant_id);
    return true;
  }

  /* ---------------- Staff management ---------------- */
  async function createStaff(tenantId, d) {
    const salt = Config.randomSalt();
    const hash = await Config.hashPin(d.pin, salt);
    const now = DB.nowISO(); const id = DB.uid('stf');
    DB.run(`INSERT INTO staff(id,tenant_id,name,username,pin_hash,salt,role,active,updated_at,created_at)
            VALUES(?,?,?,?,?,?,?,1,?,?)`,
      [id, tenantId, d.name, d.username.toLowerCase(), hash, salt, d.role, now, now]);
    Sync.queue('staff', id, 'create',
      { id, tenant_id: tenantId, name: d.name, username: d.username.toLowerCase(),
        pin_hash: hash, salt, role: d.role, active: 1, updated_at: now, created_at: now }, tenantId);
    return id;
  }

  // Render the staff table for a tenant (defaults to the active shop, used by
  // Settings). The Admin tab passes an explicit tenant.
  function renderStaff(tenantId) {
    const tid = tenantId || Config.activeTenantId();
    const rows = DB.all('SELECT * FROM staff WHERE tenant_id = ? ORDER BY role DESC, name', [tid]);
    const body = $('#staffTable tbody'); if (!body) return;
    body.innerHTML = rows.map((r) => `<tr>
      <td>${esc(r.name)}</td><td>${esc(r.username)}</td>
      <td><span class="badge">${esc(r.role)}</span></td>
      <td>${r.active ? '<span class="badge ok">Active</span>' : '<span class="badge">Disabled</span>'}</td>
      <td><div class="row-actions">
        <button class="btn small" data-editstaff="${r.id}">Edit</button>
        <button class="btn small" data-delstaff="${r.id}">${r.active ? 'Disable' : 'Enable'}</button>
        <button class="btn small danger" data-removestaff="${r.id}">Delete</button>
      </div></td>
    </tr>`).join('') || '<tr><td colspan="5" class="muted center">No staff yet.</td></tr>';
    body.dataset.tenant = tid;
  }

  function staffModal(tenantId, staffId, after) {
    const editing = !!staffId;
    const s = editing ? DB.get('SELECT * FROM staff WHERE id = ?', [staffId]) : { role: 'cashier' };
    openModal(`
      <header><h3>${editing ? 'Edit' : 'New'} staff member</h3><button class="x" data-close>×</button></header>
      <div class="body">
        <label>Full name</label><input id="stName" value="${esc(s.name || '')}">
        <div class="grid2">
          <div><label>Username</label><input id="stUser" value="${esc(s.username || '')}" ${editing ? 'disabled' : ''}></div>
          <div><label>Role</label><select id="stRole">
            <option value="cashier" ${s.role === 'cashier' ? 'selected' : ''}>Cashier (sell only)</option>
            <option value="manager" ${s.role === 'manager' ? 'selected' : ''}>Manager (full access)</option>
          </select></div>
        </div>
        <label>${editing ? 'New PIN (leave blank to keep current)' : 'PIN'}</label>
        <input id="stPin" type="password" inputmode="numeric" placeholder="${editing ? '••••' : 'PIN'}">
      </div>
      <div class="foot"><button class="btn ghost" data-close>Cancel</button><button class="btn brand" id="stSave">Save</button></div>`);
    const m = $('#modal');
    $$('[data-close]', m).forEach((b) => b.addEventListener('click', closeModal));
    $('#stSave', m).addEventListener('click', async () => {
      const name = $('#stName', m).value.trim();
      const user = $('#stUser', m).value.trim().toLowerCase();
      const role = $('#stRole', m).value;
      const pin = $('#stPin', m).value;
      if (!name || (!editing && !user)) { toast('Name and username required', 'err'); return; }
      const now = DB.nowISO();
      if (editing) {
        let hash = s.pin_hash, salt = s.salt;
        if (pin) { salt = Config.randomSalt(); hash = await Config.hashPin(pin, salt); }
        DB.run('UPDATE staff SET name=?,role=?,pin_hash=?,salt=?,active=1,updated_at=? WHERE id=?',
          [name, role, hash, salt, now, staffId]);
        Sync.queue('staff', staffId, 'update',
          { id: staffId, tenant_id: s.tenant_id, name, role, pin_hash: hash, salt, active: 1, updated_at: now }, s.tenant_id);
      } else {
        // Enforce unique username within the tenant.
        const dupe = DB.get('SELECT id FROM staff WHERE tenant_id=? AND lower(username)=? AND active=1', [tenantId, user]);
        if (dupe) { toast('That username is taken', 'err'); return; }
        if (!pin) { toast('PIN required', 'err'); return; }
        await createStaff(tenantId, { name, username: user, pin, role });
      }
      DB.persistNow(); closeModal();
      if (after) after(); else renderStaff(tenantId);
      toast('Saved', 'ok');
    });
  }

  function toggleStaff(staffId, after) {
    const s = DB.get('SELECT * FROM staff WHERE id = ?', [staffId]);
    // Never disable the last active manager of a tenant.
    if (s.active && s.role === 'manager') {
      const mgrs = DB.get("SELECT COUNT(*) AS n FROM staff WHERE tenant_id=? AND role='manager' AND active=1", [s.tenant_id]);
      if (mgrs && mgrs.n <= 1) { toast('Keep at least one active manager', 'err'); return; }
    }
    const na = s.active ? 0 : 1; const now = DB.nowISO();
    DB.run('UPDATE staff SET active=?, updated_at=? WHERE id=?', [na, now, staffId]);
    Sync.queue('staff', staffId, 'update', { id: staffId, tenant_id: s.tenant_id, active: na, updated_at: now }, s.tenant_id);
    DB.persistNow();
    if (after) after(); else renderStaff(s.tenant_id);
  }

  // Permanently delete a staff member. Removes them locally and tells the cloud
  // (and other registers) to deactivate the account, so they can no longer log in.
  function deleteStaff(staffId, after) {
    const s = DB.get('SELECT * FROM staff WHERE id = ?', [staffId]);
    if (!s) return;
    if (s.active && s.role === 'manager') {
      const mgrs = DB.get("SELECT COUNT(*) AS n FROM staff WHERE tenant_id=? AND role='manager' AND active=1", [s.tenant_id]);
      if (mgrs && mgrs.n <= 1) { toast('Keep at least one active manager', 'err'); return; }
    }
    if (!confirm('Permanently delete ' + s.name + '? They will no longer be able to sign in.')) return;
    const now = DB.nowISO();
    DB.run('DELETE FROM staff WHERE id = ?', [staffId]);
    Sync.queue('staff', staffId, 'update', { id: staffId, tenant_id: s.tenant_id, active: 0, updated_at: now }, s.tenant_id);
    DB.persistNow();
    if (after) after(); else renderStaff(s.tenant_id);
    toast('Staff member deleted', 'ok');
  }

  // Admin-side staff manager: a self-contained modal for any tenant.
  function adminStaffModal(tenantId) {
    const t = DB.get('SELECT * FROM tenants WHERE id = ?', [tenantId]);
    const rows = DB.all('SELECT * FROM staff WHERE tenant_id = ? ORDER BY role DESC, name', [tenantId]);
    const rerender = () => adminStaffModal(tenantId);
    openModal(`
      <header><h3>Staff · ${esc(t.name)}</h3><button class="x" data-close>×</button></header>
      <div class="body">
        <div class="toolbar"><button class="btn brand small" id="aAddStaff">+ Staff</button></div>
        <div class="table-wrap"><table class="data"><thead><tr><th>Name</th><th>Username</th><th>Role</th><th>Status</th><th></th></tr></thead>
        <tbody>${rows.map((r) => `<tr>
          <td>${esc(r.name)}</td><td>${esc(r.username)}</td><td><span class="badge">${esc(r.role)}</span></td>
          <td>${r.active ? '<span class="badge ok">Active</span>' : '<span class="badge">Disabled</span>'}</td>
          <td><div class="row-actions">
            <button class="btn small" data-astaffedit="${r.id}">Edit</button>
            <button class="btn small" data-astafftog="${r.id}">${r.active ? 'Disable' : 'Enable'}</button>
            <button class="btn small danger" data-astaffdel="${r.id}">Delete</button>
          </div></td></tr>`).join('') || '<tr><td colspan="5" class="muted center">No staff yet.</td></tr>'}
        </tbody></table></div>
      </div>
      <div class="foot"><button class="btn ghost" data-close>Close</button></div>`, true);
    const m = $('#modal');
    $$('[data-close]', m).forEach((b) => b.addEventListener('click', closeModal));
    $('#aAddStaff', m).addEventListener('click', () => staffModal(tenantId, null, rerender));
    $$('[data-astaffedit]', m).forEach((b) => b.addEventListener('click', () => staffModal(tenantId, b.dataset.astaffedit, rerender)));
    $$('[data-astafftog]', m).forEach((b) => b.addEventListener('click', () => toggleStaff(b.dataset.astafftog, rerender)));
    $$('[data-astaffdel]', m).forEach((b) => b.addEventListener('click', () => deleteStaff(b.dataset.astaffdel, rerender)));
  }

  /* ---------------- Status pills ---------------- */
  function updateNetPill() {
    const on = navigator.onLine;
    $('#netDot').className = 'dot ' + (on ? 'on' : 'off');
    $('#netText').textContent = on ? 'Online' : 'Offline';
  }
  function updateSyncPill(state) {
    const pending = Sync.pendingCount();
    const dot = $('#syncDot'); const txt = $('#syncText');
    const dot2 = $('#syncDot2');
    if (!Sync.configured()) {
      dot.className = 'dot warn'; txt.textContent = 'Local only';
    } else if (state && state.state === 'syncing') {
      dot.className = 'dot warn'; txt.textContent = 'Syncing…';
    } else if (state && state.state === 'error') {
      dot.className = 'dot off'; txt.textContent = 'Sync error (' + pending + ')';
    } else if (pending > 0) {
      dot.className = 'dot warn'; txt.textContent = pending + ' pending';
    } else {
      dot.className = 'dot on'; txt.textContent = 'Synced';
    }
    if (dot2) dot2.className = dot.className;
    const last = DB.getSetting('last_sync_at');
    if ($('#lastSync')) $('#lastSync').textContent = last ? 'Last sync ' + new Date(last).toLocaleString() : 'Never synced';
  }

  /* ---------------- CSV export ---------------- */
  function downloadCSV(name, rows) {
    const csv = rows.map((r) => r.map((c) => `"${String(c == null ? '' : c).replace(/"/g, '""')}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name; a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  // Build a readable multi-sheet Excel workbook for the ACTIVE shop.
  function exportWorkbook() {
    if (typeof XLSX === 'undefined') { toast('Excel engine still loading — try again', 'err'); return; }
    const t = Config.activeTenant(); const tid = t.id;
    const wb = XLSX.utils.book_new();
    const add = (name, rows) => XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(rows.length ? rows : [{}]), name.slice(0, 31));

    add('Products', DB.all(`SELECT p.name AS Product, p.category AS Category, v.name AS Variation,
        v.sku AS SKU, v.barcode AS Barcode, v.price AS Price, v.cost AS Cost, v.stock AS Stock,
        v.low_stock_threshold AS LowAt, s.name AS Supplier
      FROM variations v JOIN products p ON p.id=v.product_id
      LEFT JOIN suppliers s ON s.id=v.supplier_id
      WHERE v.tenant_id=? AND v.active=1 ORDER BY p.name, v.price`, [tid]));

    add('Suppliers', DB.all(`SELECT name AS Supplier, contact AS Contact, phone AS Phone,
        email AS Email, address AS Address FROM suppliers WHERE tenant_id=? ORDER BY name`, [tid]));

    add('Sales', DB.all(`SELECT receipt_no AS Receipt, order_no AS OrderNo, created_at AS Time,
        item_count AS Items, subtotal AS Net, vat_amount AS VAT, service_charge AS Service,
        total AS Total, cash_received AS Cash, change_due AS Change, cashier AS Cashier,
        currency AS Currency, (CASE WHEN synced=1 THEN 'yes' ELSE 'no' END) AS Synced
      FROM sales WHERE tenant_id=? ORDER BY created_at DESC`, [tid]));

    add('Sale items', DB.all(`SELECT s.receipt_no AS Receipt, si.name AS Item, si.sku AS SKU,
        si.qty AS Qty, si.unit_price AS Price, si.line_total AS LineTotal
      FROM sale_items si JOIN sales s ON s.id=si.sale_id
      WHERE si.tenant_id=? ORDER BY s.created_at DESC`, [tid]));

    // Staff WITHOUT password hashes.
    add('Staff', DB.all(`SELECT name AS Name, username AS Username, role AS Role,
        (CASE WHEN active=1 THEN 'active' ELSE 'disabled' END) AS Status
      FROM staff WHERE tenant_id=? ORDER BY role DESC, name`, [tid]));

    const safe = (t.name || 'shop').replace(/[^A-Za-z0-9]+/g, '-').toLowerCase();
    XLSX.writeFile(wb, 'totals-pos-' + safe + '-' + Config.todayKey() + '.xlsx');
    toast('Excel workbook downloaded', 'ok');
  }

  /* ---------------- View switching ---------------- */
  function switchView(name) {
    $$('.tab').forEach((t) => t.classList.toggle('active', t.dataset.view === name));
    $$('.view').forEach((v) => v.classList.toggle('active', v.id === 'view-' + name));
    if (name === 'inventory') renderInventory();
    if (name === 'suppliers') renderSuppliers();
    if (name === 'reports') { repShowFigures = false; repFrom = repTo = repSearch = ''; renderReports(); }
    if (name === 'admin') renderAdmin();
    if (name === 'settings') loadSettings();
  }

  function loadSettings() {
    $('#setDevice').value = Config.deviceName();
    $('#setCashier').value = DB.getSetting('cashier_name') || '';
    // Sales / VAT / service charge for the active shop.
    const t = Config.activeTenant() || {};
    $('#setVatEnabled').checked = !!t.vat_enabled;
    $('#setVatRate').value = t.vat_rate != null ? t.vat_rate : 15;
    $('#setVatInclusive').value = t.vat_inclusive ? '1' : '0';
    $('#setVatShow').checked = t.vat_show_receipt !== 0;
    $('#setSvcEnabled').checked = !!t.service_charge_enabled;
    $('#setSvcRate').value = t.service_charge_rate != null ? t.service_charge_rate : 0;
    $('#setSvcShow').checked = t.service_charge_show_receipt !== 0;
    $('#logoPrev').src = t.logo || './icons/icon.svg';
    $('#setLogoOnReceipt').checked = t.logo_on_receipt !== 0;
    $('#setOrderNoOnReceipt').checked = t.order_no_on_receipt !== 0;
    let cats = []; try { cats = JSON.parse(t.categories || '[]'); } catch (e) {}
    $('#setCategories').value = cats.join('\n');
    renderStaff();
    updateSyncPill();
  }

  /* ---------------- Wire up events ---------------- */
  function wire() {
    // Tabs
    $('#tabs').addEventListener('click', (e) => { const b = e.target.closest('.tab'); if (b) switchView(b.dataset.view); });

    // Login / sign out
    $('#loginBtn').addEventListener('click', attemptLogin);
    $('#loginShop').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('#loginUser').focus(); });
    $('#loginPin').addEventListener('keydown', (e) => { if (e.key === 'Enter') attemptLogin(); });
    $('#loginUser').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('#loginPin').focus(); });
    $('#signOutBtn').addEventListener('click', signOut);

    // POS delegation
    $('#tiles').addEventListener('click', (e) => { const b = e.target.closest('[data-prod]'); if (b) pickProduct(b.dataset.prod); });
    $('#cats').addEventListener('click', (e) => { const b = e.target.closest('[data-cat]'); if (b) { activeCat = b.dataset.cat; renderPOS(); } });
    $('#cartItems').addEventListener('click', (e) => {
      const inc = e.target.closest('[data-inc]'); const dec = e.target.closest('[data-dec]');
      if (inc) cartSetQty(inc.dataset.inc, 1); if (dec) cartSetQty(dec.dataset.dec, -1);
    });
    $('#chargeBtn').addEventListener('click', openCharge);
    $('#scanSellBtn').addEventListener('click', () => openScanner({
      title: 'Scan items to sell', continuous: true, onCode: addByBarcode
    }));
    $('#clearBtn').addEventListener('click', () => { if (cart.length && confirm('Clear the current sale?')) { cart = []; renderCart(); } });

    // Inventory
    $('#scanAddBtn').addEventListener('click', () => openScanner({
      title: 'Scan item to add', continuous: false,
      onCode: (code) => {
        const row = Scan.lookup(code);
        if (row) { toast('Already in inventory: ' + row.product_name); productModal(row.pid); }
        else { toast('New item — code ' + code); productModal(null, code); }
      }
    }));
    $('#addProductBtn').addEventListener('click', () => productModal(null));
    $('#invSearch').addEventListener('input', (e) => { invFilter = e.target.value; renderInventory(); });
    $('#invTable').addEventListener('click', (e) => {
      const ed = e.target.closest('[data-editprod]'); const rs = e.target.closest('[data-restock]');
      if (ed) productModal(ed.dataset.editprod); if (rs) restockModal(rs.dataset.restock);
    });
    $('#exportInvBtn').addEventListener('click', () => {
      const tid = Config.activeTenantId();
      const rows = DB.all(`SELECT p.name AS product, v.name AS variation, v.sku, v.price, v.cost, v.stock, v.low_stock_threshold
        FROM variations v JOIN products p ON p.id=v.product_id WHERE v.tenant_id=? AND v.active=1`, [tid]);
      downloadCSV('inventory.csv', [['Product', 'Variation', 'SKU', 'Price', 'Cost', 'Stock', 'LowAt'],
        ...rows.map((r) => [r.product, r.variation, r.sku, r.price, r.cost, r.stock, r.low_stock_threshold])]);
    });

    // Suppliers
    $('#addSupplierBtn').addEventListener('click', () => supplierModal(null));
    $('#supSearch').addEventListener('input', (e) => { supFilter = e.target.value; renderSuppliers(); });
    $('#supTable').addEventListener('click', (e) => { const b = e.target.closest('[data-editsup]'); if (b) supplierModal(b.dataset.editsup); });

    // Reports
    $('#repShowFigures').addEventListener('change', (e) => { repShowFigures = e.target.checked; renderReports(); });
    $('#repFrom').addEventListener('change', (e) => { repFrom = e.target.value; renderReports(); });
    $('#repTo').addEventListener('change', (e) => { repTo = e.target.value; renderReports(); });
    $('#repSearch').addEventListener('input', (e) => { repSearch = e.target.value; renderReports(); });
    $('#repClearFilter').addEventListener('click', () => { repFrom = repTo = repSearch = ''; renderReports(); });
    $('#repAnalyticsBtn').addEventListener('click', () => {
      const t = Config.activeTenant();
      if (!t || t.analytics_enabled !== 1) { toast('Report analytics is off — an administrator enables it per shop.', 'err'); return; }
      openAnalytics();
    });
    $('#salesTable').addEventListener('click', (e) => {
      const rp = e.target.closest('[data-reprint]'); if (rp) return reprint(rp.dataset.reprint);
      const ed = e.target.closest('[data-editsale]'); if (ed) return editSale(ed.dataset.editsale);
      const vd = e.target.closest('[data-voidsale]'); if (vd) return voidSale(vd.dataset.voidsale);
    });
    $('#exportSalesBtn').addEventListener('click', () => {
      if (!repShowFigures) { toast('Tick “Show sales & income figures” first', 'err'); return; }
      const tid = Config.activeTenantId();
      const rows = DB.all('SELECT receipt_no,created_at,item_count,subtotal,vat_amount,total,cash_received,change_due,synced FROM sales WHERE tenant_id=? ORDER BY created_at DESC', [tid]);
      downloadCSV('sales.csv', [['Receipt', 'Time', 'Items', 'Net', 'VAT', 'Total', 'Cash', 'Change', 'Synced'],
        ...rows.map((r) => [r.receipt_no, r.created_at, r.item_count, r.subtotal, r.vat_amount, r.total, r.cash_received, r.change_due, r.synced])]);
    });

    // Admin
    $('#adminUnlockBtn').addEventListener('click', () => {
      if ($('#adminPinInput').value === Config.adminPin()) { sessionStorage.setItem('admin_ok', '1'); renderAdmin(); }
      else toast('Wrong PIN', 'err');
    });
    $('#adminPinInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('#adminUnlockBtn').click(); });
    $('#adminLockBtn').addEventListener('click', () => { sessionStorage.removeItem('admin_ok'); renderAdmin(); });
    $('#addTenantBtn').addEventListener('click', () => tenantModal(null));
    $('#tenantSearch').addEventListener('input', (e) => { tenantFilter = e.target.value; renderAdmin(); });
    $('#tenantTable').addEventListener('click', (e) => {
      const ed = e.target.closest('[data-edittenant]'); const use = e.target.closest('[data-usetenant]');
      const tog = e.target.closest('[data-toggletenant]'); const stf = e.target.closest('[data-stafftenant]');
      if (ed) tenantModal(ed.dataset.edittenant);
      if (stf) adminStaffModal(stf.dataset.stafftenant);
      // "Open" signs in with a device-admin override (full access, no PIN reprompt).
      if (use) {
        const t = DB.get('SELECT * FROM tenants WHERE id=?', [use.dataset.usetenant]);
        signInAs({ tenant_id: t.id, admin: true, role: 'admin', name: 'Administrator' });
      }
      if (tog) {
        const t = DB.get('SELECT * FROM tenants WHERE id=?', [tog.dataset.toggletenant]);
        const ns = t.status === 'suspended' ? 'active' : 'suspended';
        DB.run('UPDATE tenants SET status=?, updated_at=? WHERE id=?', [ns, DB.nowISO(), t.id]);
        Sync.queue('tenant', t.id, 'update', { id: t.id, status: ns }, t.id);
        DB.persistNow(); updateTopbar(); renderAdmin(); toast('Tenant ' + ns);
      }
    });

    // Settings — staff (manager-managed, current shop)
    $('#addStaffBtn').addEventListener('click', () => staffModal(Config.activeTenantId(), null, () => renderStaff()));
    $('#staffTable').addEventListener('click', (e) => {
      const ed = e.target.closest('[data-editstaff]');
      const del = e.target.closest('[data-delstaff]');
      const rem = e.target.closest('[data-removestaff]');
      if (ed) staffModal(Config.activeTenantId(), ed.dataset.editstaff, () => renderStaff());
      if (del) toggleStaff(del.dataset.delstaff, () => renderStaff());
      if (rem) deleteStaff(rem.dataset.removestaff, () => renderStaff());
    });

    // Settings — sales / VAT / service charge
    $('#saveTaxBtn').addEventListener('click', () => {
      const t = Config.activeTenant(); const now = DB.nowISO();
      const vals = {
        vat_enabled: $('#setVatEnabled').checked ? 1 : 0,
        vat_rate: parseFloat($('#setVatRate').value) || 0,
        vat_inclusive: parseInt($('#setVatInclusive').value, 10),
        vat_show_receipt: $('#setVatShow').checked ? 1 : 0,
        service_charge_enabled: $('#setSvcEnabled').checked ? 1 : 0,
        service_charge_rate: parseFloat($('#setSvcRate').value) || 0,
        service_charge_show_receipt: $('#setSvcShow').checked ? 1 : 0
      };
      DB.run(`UPDATE tenants SET vat_enabled=?,vat_rate=?,vat_inclusive=?,vat_show_receipt=?,
               service_charge_enabled=?,service_charge_rate=?,service_charge_show_receipt=?,updated_at=? WHERE id=?`,
        [vals.vat_enabled, vals.vat_rate, vals.vat_inclusive, vals.vat_show_receipt,
         vals.service_charge_enabled, vals.service_charge_rate, vals.service_charge_show_receipt, now, t.id]);
      Sync.queue('tenant', t.id, 'update', Object.assign({ id: t.id, updated_at: now }, vals), t.id);
      DB.persistNow();
      renderCart(); renderPOS();
      toast('Tax settings saved', 'ok');
    });

    // Settings — logo / branding
    $('#brandBtn').addEventListener('click', () => { if (canManage()) $('#logoFile').click(); });
    $('#logoUploadBtn').addEventListener('click', () => $('#logoFile').click());
    $('#logoClearBtn').addEventListener('click', () => saveLogo(null));
    $('#logoFile').addEventListener('change', (e) => { const f = e.target.files[0]; if (f) saveLogo(f); e.target.value = ''; });
    $('#saveBrandingBtn').addEventListener('click', () => {
      const t = Config.activeTenant(); const now = DB.nowISO();
      const logoOn = $('#setLogoOnReceipt').checked ? 1 : 0;
      const orderOn = $('#setOrderNoOnReceipt').checked ? 1 : 0;
      DB.run('UPDATE tenants SET logo_on_receipt=?, order_no_on_receipt=?, updated_at=? WHERE id=?', [logoOn, orderOn, now, t.id]);
      Sync.queue('tenant', t.id, 'update', { id: t.id, logo_on_receipt: logoOn, order_no_on_receipt: orderOn, updated_at: now }, t.id);
      DB.persistNow(); toast('Branding saved', 'ok');
    });

    // Settings — product categories (headers)
    $('#saveCategoriesBtn').addEventListener('click', () => {
      const list = $('#setCategories').value.split('\n').map((s) => s.trim()).filter(Boolean);
      // de-dupe, keep order
      const seen = new Set(); const clean = [];
      list.forEach((c) => { const k = c.toLowerCase(); if (!seen.has(k)) { seen.add(k); clean.push(c); } });
      setTenantCategories(clean);
      toast('Categories saved', 'ok');
    });

    // Settings — device (manager-safe; no admin details here)
    $('#saveDeviceBtn').addEventListener('click', () => {
      DB.setSetting('device_name', $('#setDevice').value.trim() || 'Register 1');
      DB.setSetting('cashier_name', $('#setCashier').value.trim() || 'Cashier');
      DB.persistNow(); toast('Saved', 'ok');
    });
    // Admin-only: change the admin PIN (lives behind the admin unlock).
    $('#saveAdminPinBtn').addEventListener('click', () => {
      if (!isAdminUnlocked()) { toast('Unlock admin first', 'err'); return; }
      const a = $('#setAdminPin').value.trim(), b = $('#setAdminPin2').value.trim();
      if (a.length < 4) { toast('Use at least 4 digits', 'err'); return; }
      if (a !== b) { toast('PINs do not match', 'err'); return; }
      DB.setSetting('admin_pin', a); DB.persistNow();
      $('#setAdminPin').value = ''; $('#setAdminPin2').value = '';
      toast('Admin PIN changed', 'ok');
    });
    $('#saveApiBtn').addEventListener('click', () => {
      DB.setSetting('api_base', $('#setApiBase').value.trim()); DB.persistNow();
      updateSyncPill(); Sync.run(true); toast('Cloud settings saved', 'ok');
    });
    // Reset to the embedded default (removes the per-device override).
    $('#resetApiBtn').addEventListener('click', () => {
      DB.run('DELETE FROM settings WHERE key = ?', ['api_base']); DB.persistNow();
      $('#setApiBase').value = Config.DEFAULT_API_BASE;
      updateSyncPill(); Sync.run(true); toast('Reset to default cloud address', 'ok');
    });
    // Turn cloud off for this device (explicit empty = offline).
    $('#offlineApiBtn').addEventListener('click', () => {
      if (!confirm('Run this register OFFLINE? It will stop syncing to the cloud until you set the address again.')) return;
      DB.setSetting('api_base', ''); DB.persistNow();
      $('#setApiBase').value = '';
      updateSyncPill(); toast('Cloud sync turned off (offline)', 'ok');
    });
    $('#testCloudBtn').addEventListener('click', async () => {
      const el = $('#cloudTestResult');
      const base = $('#setApiBase').value.trim();
      el.style.color = 'var(--muted)'; el.textContent = 'Testing connection…';
      try {
        const r = await Sync.test(base);
        el.style.color = 'var(--ok)';
        el.textContent = '✓ Connected — ' + r.tenants + ' tenant(s) on the server, cursor ' + r.cursor + '.';
        toast('Cloud connection OK', 'ok');
      } catch (e) {
        el.style.color = 'var(--danger)';
        el.textContent = '✗ ' + ((e && e.message) || e) + '  — check the URL is your function domain (no /api) and the function is deployed.';
        toast('Connection failed', 'err');
      }
    });
    $('#syncNowBtn').addEventListener('click', () => { if (!Sync.configured()) { toast('Set an API base URL first', 'err'); return; } Sync.run(true); });
    $('#backupBtn').addEventListener('click', () => {
      const blob = new Blob([DB.export()], { type: 'application/octet-stream' });
      const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
      a.download = 'totals-pos-backup-' + new Date().toISOString().slice(0, 10) + '.sqlite'; a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    });
    $('#backupXlsxBtn').addEventListener('click', exportWorkbook);
    $('#restoreBtn').addEventListener('click', () => $('#restoreFile').click());
    $('#restoreFile').addEventListener('change', async (e) => {
      const f = e.target.files[0]; if (!f) return;
      if (!confirm('Restore will replace ALL current data on this device. Continue?')) return;
      const buf = new Uint8Array(await f.arrayBuffer());
      await DB.import(buf); toast('Restored — reloading'); setTimeout(() => location.reload(), 800);
    });
    $('#wipeBtn').addEventListener('click', () => { if (confirm('Erase ALL local data on this device? This cannot be undone.')) DB.wipe(); });

    // Network + sync listeners
    window.addEventListener('online', updateNetPill);
    window.addEventListener('offline', updateNetPill);
    Sync.onChange((state) => { updateSyncPill(state); if (state.state === 'synced') { renderPOS(); if ($('#view-inventory').classList.contains('active')) renderInventory(); } });

    // Hardware barcode scanners emulate a keyboard: they send characters very
    // fast and finish with Enter. On the Sell screen (no field focused, no
    // modal open) we buffer those keystrokes and treat the line as a scan.
    let scanBuf = '', scanLast = 0;
    document.addEventListener('keydown', (e) => {
      const posActive = $('#view-pos').classList.contains('active');
      const el = document.activeElement;
      const inField = el && /^(INPUT|SELECT|TEXTAREA)$/.test(el.tagName);
      const modalOpen = $('#modalBack').classList.contains('open') || $('#loginBack').classList.contains('open');
      if (!posActive || inField || modalOpen) { scanBuf = ''; return; }
      const now = Date.now();
      if (now - scanLast > 120) scanBuf = ''; // reset between human keystrokes
      scanLast = now;
      if (e.key === 'Enter') { if (scanBuf.length >= 3) addByBarcode(scanBuf); scanBuf = ''; return; }
      if (e.key && e.key.length === 1) scanBuf += e.key;
    });
  }

  /* ---------------- Service worker + update flow ---------------- */
  function registerSW() {
    if (!('serviceWorker' in navigator)) return;
    navigator.serviceWorker.register('./sw.js').then((reg) => {
      // Detect a newly installed worker waiting to take over.
      function checkWaiting() {
        if (reg.waiting) showUpdateBanner(reg.waiting);
      }
      checkWaiting();
      reg.addEventListener('updatefound', () => {
        const nw = reg.installing;
        if (!nw) return;
        nw.addEventListener('statechange', () => {
          if (nw.state === 'installed' && navigator.serviceWorker.controller) showUpdateBanner(nw);
        });
      });
      // Poll for updates so registers pick up new versions we push.
      setInterval(() => reg.update().catch(() => {}), 60 * 60 * 1000);
      // Report version.
      const mc = new MessageChannel();
      mc.port1.onmessage = (e) => { if (e.data && e.data.version) $('#appVersion').textContent = e.data.version; };
      if (reg.active) reg.active.postMessage({ type: 'GET_VERSION' }, [mc.port2]);
    }).catch(() => {});

    // Only reload when an UPDATE takes control, never on the very first
    // registration (that first claim is not a new version).
    const hadController = !!navigator.serviceWorker.controller;
    let reloaded = false;
    navigator.serviceWorker.addEventListener('controllerchange', () => {
      if (!hadController || reloaded) return;
      reloaded = true; location.reload();
    });
  }
  function showUpdateBanner(worker) {
    const banner = $('#updateBanner'); banner.classList.add('show');
    $('#updateBtn').onclick = () => { worker.postMessage({ type: 'SKIP_WAITING' }); };
  }

  /* ---------------- Boot ---------------- */
  async function boot() {
    await DB.init();
    wire();
    updateNetPill();
    updateSyncPill();
    Sync.start();
    registerSW();

    // Gate the app behind a per-tenant staff login.
    if (restoreSession()) {
      applyRoleGating();
      updateTopbar();
      renderPOS(); renderCart();
    } else {
      Config.setSession(null);
      showLogin();
    }
  }

  window.addEventListener('DOMContentLoaded', () => {
    boot().catch((e) => {
      console.error(e);
      document.body.innerHTML = '<div style="padding:40px;color:#fff;font-family:system-ui">' +
        '<h2>Failed to start Totals POS</h2><pre>' + Config.escapeHtml(e && e.message) + '</pre></div>';
    });
  });
})();
