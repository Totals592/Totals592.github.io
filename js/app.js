/*
 * Totals POS - Application controller
 * ---------------------------------------------------------------------------
 * Wires the UI to the local SQLite database, the sync engine and receipts.
 */
(function () {
  'use strict';

  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const money = (n) => Config.money(n, (Config.activeTenant() || {}).currency || 'GHS');
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
  function closeModal() { $('#modalBack').classList.remove('open'); $('#modal').innerHTML = ''; }
  $('#modalBack').addEventListener('click', (e) => { if (e.target.id === 'modalBack') closeModal(); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeModal(); });

  /* ---------------- Cart state ---------------- */
  let cart = []; // {variation_id, product_id, name, sku, unit_price, qty, track_stock, stock}

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
        sku: v.sku, unit_price: v.price, qty: 1,
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
    const gross = cart.reduce((s, c) => s + c.unit_price * c.qty, 0);
    let net, vat, total;
    if (t.vat_inclusive) {
      const b = Config.vatBreakdown(gross, t.vat_rate, true);
      net = b.net; vat = b.vat; total = gross;
    } else {
      const b = Config.vatBreakdown(gross, t.vat_rate, false);
      net = b.net; vat = b.vat; total = b.gross;
    }
    return { net, vat, total, count: cart.reduce((s, c) => s + c.qty, 0) };
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
    $('#sumNet').textContent = money(tot.net);
    $('#sumVat').textContent = money(tot.vat);
    $('#sumTotal').textContent = money(tot.total);
    $('#vatLabel').textContent = t.vat_rate > 0
      ? `VAT (${t.vat_rate}%${t.vat_inclusive ? ' incl.' : ''})` : 'VAT';
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
      const priceLabel = p.variations.length > 1
        ? 'from ' + money(Math.min(...p.variations.map((x) => x.price)))
        : money(v.price);
      const stock = p.variations.reduce((s, x) => s + (x.track_stock ? x.stock : Infinity), 0);
      const tracked = p.variations.some((x) => x.track_stock);
      const low = tracked && stock <= Math.max(...p.variations.map((x) => x.low_stock_threshold || 0));
      const out = tracked && stock <= 0;
      return `<button class="tile ${out ? 'out' : ''}" data-prod="${p.id}">
        <span class="swatch" style="background:${esc(p.color || '#334155')}"></span>
        ${p.image ? `<span class="img" style="background-image:url('${esc(p.image)}')"></span>` : ''}
        ${low ? `<span class="low">${out ? 'Out' : 'Low: ' + stock}</span>` : ''}
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
            return `<button class="tile ${out ? 'out' : ''}" data-var="${v.id}" ${out ? 'disabled' : ''}>
              <span class="name">${esc(v.name)}</span>
              <span class="price">${money(v.price)}</span>
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
    const now = DB.nowISO();
    const change = cash - tot.total;

    DB.run(`INSERT INTO sales(id,tenant_id,receipt_no,subtotal,vat_amount,total,cash_received,change_due,
             item_count,cashier,vat_inclusive,vat_rate,currency,status,synced,created_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [saleId, t.id, receiptNo, tot.net, tot.vat, tot.total, cash, change, tot.count,
       Config.cashierName(), t.vat_inclusive ? 1 : 0, t.vat_rate, t.currency, 'completed', 0, now]);

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
      receipt_no: receiptNo, subtotal: tot.net, vat_amount: tot.vat, total: tot.total,
      cash_received: cash, change_due: change, cashier: Config.cashierName(),
      vat_inclusive: t.vat_inclusive, vat_rate: t.vat_rate, created_at: now
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

  function productModal(pid) {
    const tid = Config.activeTenantId();
    const editing = !!pid;
    const p = editing ? DB.get('SELECT * FROM products WHERE id = ?', [pid])
                      : { id: '', name: '', category: 'General', color: '#334155', image: '', description: '', active: 1 };
    let vars = editing ? DB.all('SELECT * FROM variations WHERE product_id = ? ORDER BY price', [pid]) : [];
    if (!vars.length) vars = [{ id: '', name: 'Default', sku: '', price: 0, cost: 0, stock: 0, track_stock: 1, low_stock_threshold: 5, supplier_id: '', active: 1 }];
    const suppliers = DB.all('SELECT * FROM suppliers WHERE tenant_id = ? ORDER BY name', [tid]);
    let image = p.image || '';

    function varRow(v, i) {
      return `<div class="card" style="padding:10px" data-vrow="${i}">
        <div class="grid2">
          <div><label>Variation</label><input data-v="name" value="${esc(v.name || '')}"></div>
          <div><label>SKU</label><input data-v="sku" value="${esc(v.sku || '')}"></div>
          <div><label>Price</label><input data-v="price" type="number" step="0.01" value="${v.price}"></div>
          <div><label>Cost</label><input data-v="cost" type="number" step="0.01" value="${v.cost}"></div>
          <div><label>Stock</label><input data-v="stock" type="number" step="1" value="${v.stock}"></div>
          <div><label>Low-stock alert at</label><input data-v="low_stock_threshold" type="number" step="1" value="${v.low_stock_threshold}"></div>
          <div><label>Supplier</label><select data-v="supplier_id">
            <option value="">—</option>
            ${suppliers.map((s) => `<option value="${s.id}" ${s.id === v.supplier_id ? 'selected' : ''}>${esc(s.name)}</option>`).join('')}
          </select></div>
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
          <div><label>Category</label><input id="pCat" value="${esc(p.category || '')}"></div>
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
          id: g('id'), name: g('name') || 'Default', sku: g('sku'),
          price: parseFloat(g('price')) || 0, cost: parseFloat(g('cost')) || 0,
          stock: parseFloat(g('stock')) || 0, track_stock: g('track_stock') === '1' ? 1 : 0,
          low_stock_threshold: parseFloat(g('low_stock_threshold')) || 0,
          supplier_id: g('supplier_id') || null, active: 1
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
        name, category: $('#pCat', m).value.trim() || 'General',
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
          DB.run(`UPDATE variations SET name=?,sku=?,price=?,cost=?,stock=?,track_stock=?,low_stock_threshold=?,supplier_id=?,active=1,updated_at=? WHERE id=?`,
            [v.name, v.sku, v.price, v.cost, v.stock, v.track_stock, v.low_stock_threshold, v.supplier_id, now, v.id]);
          keptIds.push(v.id);
        } else {
          const vid = DB.uid('var');
          DB.run(`INSERT INTO variations(id,product_id,tenant_id,name,sku,price,cost,stock,track_stock,low_stock_threshold,supplier_id,active,updated_at,created_at)
                  VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
            [vid, productId, tid, v.name, v.sku, v.price, v.cost, v.stock, v.track_stock, v.low_stock_threshold, v.supplier_id, 1, now, now]);
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
  function renderReports() {
    const tid = Config.activeTenantId();
    const today = new Date(); today.setHours(0, 0, 0, 0);
    const sales = DB.all('SELECT * FROM sales WHERE tenant_id = ? ORDER BY created_at DESC LIMIT 100', [tid]);
    const todaySales = sales.filter((s) => new Date(s.created_at) >= today);
    const todayTotal = todaySales.reduce((s, r) => s + r.total, 0);
    const pending = DB.get('SELECT COUNT(*) AS n FROM sales WHERE tenant_id=? AND synced=0', [tid]);
    $('#repKpis').innerHTML =
      kpi(money(todayTotal), "Today's sales") +
      kpi(todaySales.length, 'Transactions today') +
      kpi(money(todaySales.reduce((s, r) => s + r.vat_amount, 0)), 'VAT collected today') +
      kpi(pending ? pending.n : 0, 'Unsynced sales');

    $('#salesTable tbody').innerHTML = sales.map((s) => `<tr>
      <td>${esc(s.receipt_no)}</td>
      <td>${new Date(s.created_at).toLocaleString()}</td>
      <td>${s.item_count}</td><td>${money(s.total)}</td><td>${money(s.cash_received)}</td>
      <td>${s.synced ? '<span class="badge ok">Synced</span>' : '<span class="badge">Pending</span>'}</td>
      <td><button class="btn small" data-reprint="${s.id}">Receipt</button></td>
    </tr>`).join('') || '<tr><td colspan="7" class="muted center">No sales yet.</td></tr>';

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

  /* ---------------- Admin (tenant management) ---------------- */
  let tenantFilter = '';
  function isAdminUnlocked() { return sessionStorage.getItem('admin_ok') === '1'; }
  function renderAdmin() {
    const unlocked = isAdminUnlocked();
    $('#adminLock').style.display = unlocked ? 'none' : '';
    $('#adminPanel').style.display = unlocked ? '' : 'none';
    if (!unlocked) return;
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
          <button class="btn small" data-usetenant="${t.id}">Open</button>
          <button class="btn small ${t.status === 'suspended' ? 'brand' : 'danger'}" data-toggletenant="${t.id}">${t.status === 'suspended' ? 'Activate' : 'Suspend'}</button>
        </div></td>
      </tr>`;
    }).join('');
  }
  function tenantModal(tid) {
    const editing = !!tid;
    const t = editing ? DB.get('SELECT * FROM tenants WHERE id = ?', [tid])
      : { currency: 'GHS', vat_rate: 15, vat_inclusive: 1, status: 'active' };
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
      </div>
      <div class="foot"><button class="btn ghost" data-close>Cancel</button><button class="btn brand" id="tSave">Save</button></div>`, true);
    const m = $('#modal');
    $$('[data-close]', m).forEach((b) => b.addEventListener('click', closeModal));
    $('#tSave', m).addEventListener('click', () => {
      const name = $('#tName', m).value.trim();
      if (!name) { toast('Business name required', 'err'); return; }
      const now = DB.nowISO();
      const vals = {
        name, tin: $('#tTin', m).value.trim(), slug: $('#tSlug', m).value.trim(),
        phone: $('#tPhone', m).value.trim(), email: $('#tEmail', m).value.trim(),
        address: $('#tAddr', m).value.trim(), currency: $('#tCur', m).value,
        vat_rate: parseFloat($('#tVat', m).value) || 0, vat_inclusive: parseInt($('#tVatInc', m).value, 10),
        status: $('#tStatus', m).value, receipt_footer: $('#tFooter', m).value.trim()
      };
      let id = tid;
      if (editing) {
        DB.run(`UPDATE tenants SET name=?,tin=?,slug=?,phone=?,email=?,address=?,currency=?,vat_rate=?,vat_inclusive=?,status=?,receipt_footer=?,updated_at=? WHERE id=?`,
          [vals.name, vals.tin, vals.slug, vals.phone, vals.email, vals.address, vals.currency, vals.vat_rate, vals.vat_inclusive, vals.status, vals.receipt_footer, now, tid]);
      } else {
        id = DB.uid('ten');
        DB.run(`INSERT INTO tenants(id,name,tin,slug,phone,email,address,currency,vat_rate,vat_inclusive,status,receipt_footer,updated_at,created_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
          [id, vals.name, vals.tin, vals.slug, vals.phone, vals.email, vals.address, vals.currency, vals.vat_rate, vals.vat_inclusive, vals.status, vals.receipt_footer, now, now]);
      }
      Sync.queue('tenant', id, editing ? 'update' : 'create', Object.assign({ id }, vals), id);
      DB.persistNow();
      closeModal(); populateTenants(); renderAdmin();
      toast(editing ? 'Tenant updated' : 'Tenant created', 'ok');
    });
  }

  /* ---------------- Tenant selector ---------------- */
  function populateTenants() {
    const sel = $('#tenantSelect');
    const tenants = DB.all("SELECT * FROM tenants WHERE status != 'suspended' ORDER BY name");
    const active = Config.activeTenantId();
    sel.innerHTML = tenants.map((t) => `<option value="${t.id}" ${t.id === active ? 'selected' : ''}>${esc(t.name)}</option>`).join('');
    // If active tenant got suspended, fall back to first available.
    if (tenants.length && !tenants.find((t) => t.id === active)) {
      Config.setActiveTenant(tenants[0].id); sel.value = tenants[0].id;
    }
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

  /* ---------------- View switching ---------------- */
  function switchView(name) {
    $$('.tab').forEach((t) => t.classList.toggle('active', t.dataset.view === name));
    $$('.view').forEach((v) => v.classList.toggle('active', v.id === 'view-' + name));
    if (name === 'inventory') renderInventory();
    if (name === 'suppliers') renderSuppliers();
    if (name === 'reports') renderReports();
    if (name === 'admin') renderAdmin();
    if (name === 'settings') loadSettings();
  }

  function loadSettings() {
    $('#setDevice').value = Config.deviceName();
    $('#setCashier').value = Config.cashierName();
    $('#setAdminPin').value = Config.adminPin();
    $('#setApiBase').value = DB.getSetting('api_base') || '';
    updateSyncPill();
  }

  /* ---------------- Wire up events ---------------- */
  function wire() {
    // Tabs
    $('#tabs').addEventListener('click', (e) => { const b = e.target.closest('.tab'); if (b) switchView(b.dataset.view); });

    // Tenant switch
    $('#tenantSelect').addEventListener('change', (e) => {
      Config.setActiveTenant(e.target.value); DB.persistNow();
      cart = []; renderCart(); renderPOS();
      toast('Switched to ' + Config.activeTenant().name);
    });

    // POS delegation
    $('#tiles').addEventListener('click', (e) => { const b = e.target.closest('[data-prod]'); if (b) pickProduct(b.dataset.prod); });
    $('#cats').addEventListener('click', (e) => { const b = e.target.closest('[data-cat]'); if (b) { activeCat = b.dataset.cat; renderPOS(); } });
    $('#cartItems').addEventListener('click', (e) => {
      const inc = e.target.closest('[data-inc]'); const dec = e.target.closest('[data-dec]');
      if (inc) cartSetQty(inc.dataset.inc, 1); if (dec) cartSetQty(dec.dataset.dec, -1);
    });
    $('#chargeBtn').addEventListener('click', openCharge);
    $('#clearBtn').addEventListener('click', () => { if (cart.length && confirm('Clear the current sale?')) { cart = []; renderCart(); } });
    $('#holdBtn').addEventListener('click', () => {
      if (!cart.length) return;
      sessionStorage.setItem('held_' + Config.activeTenantId(), JSON.stringify(cart));
      cart = []; renderCart(); toast('Sale held');
    });

    // Inventory
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
    $('#salesTable').addEventListener('click', (e) => { const b = e.target.closest('[data-reprint]'); if (b) reprint(b.dataset.reprint); });
    $('#exportSalesBtn').addEventListener('click', () => {
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
      const ed = e.target.closest('[data-edittenant]'); const use = e.target.closest('[data-usetenant]'); const tog = e.target.closest('[data-toggletenant]');
      if (ed) tenantModal(ed.dataset.edittenant);
      if (use) { Config.setActiveTenant(use.dataset.usetenant); populateTenants(); cart = []; renderCart(); renderPOS(); switchView('pos'); toast('Now selling as ' + Config.activeTenant().name); }
      if (tog) {
        const t = DB.get('SELECT * FROM tenants WHERE id=?', [tog.dataset.toggletenant]);
        const ns = t.status === 'suspended' ? 'active' : 'suspended';
        DB.run('UPDATE tenants SET status=?, updated_at=? WHERE id=?', [ns, DB.nowISO(), t.id]);
        Sync.queue('tenant', t.id, 'update', { id: t.id, status: ns }, t.id);
        DB.persistNow(); populateTenants(); renderAdmin(); toast('Tenant ' + ns);
      }
    });

    // Settings
    $('#saveDeviceBtn').addEventListener('click', () => {
      DB.setSetting('device_name', $('#setDevice').value.trim() || 'Register 1');
      DB.setSetting('cashier_name', $('#setCashier').value.trim() || 'Cashier');
      DB.setSetting('admin_pin', $('#setAdminPin').value.trim() || '1234');
      DB.persistNow(); toast('Saved', 'ok');
    });
    $('#saveApiBtn').addEventListener('click', () => {
      DB.setSetting('api_base', $('#setApiBase').value.trim()); DB.persistNow();
      updateSyncPill(); Sync.run(true); toast('Cloud settings saved', 'ok');
    });
    $('#syncNowBtn').addEventListener('click', () => { if (!Sync.configured()) { toast('Set an API base URL first', 'err'); return; } Sync.run(true); });
    $('#backupBtn').addEventListener('click', () => {
      const blob = new Blob([DB.export()], { type: 'application/octet-stream' });
      const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
      a.download = 'totals-pos-backup-' + new Date().toISOString().slice(0, 10) + '.sqlite'; a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    });
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
    populateTenants();
    renderPOS(); renderCart();
    // Restore a held sale if present.
    const held = sessionStorage.getItem('held_' + Config.activeTenantId());
    if (held) { try { cart = JSON.parse(held); sessionStorage.removeItem('held_' + Config.activeTenantId()); renderCart(); } catch (e) {} }
    wire();
    updateNetPill();
    updateSyncPill();
    Sync.start();
    registerSW();
  }

  window.addEventListener('DOMContentLoaded', () => {
    boot().catch((e) => {
      console.error(e);
      document.body.innerHTML = '<div style="padding:40px;color:#fff;font-family:system-ui">' +
        '<h2>Failed to start Totals POS</h2><pre>' + Config.escapeHtml(e && e.message) + '</pre></div>';
    });
  });
})();
