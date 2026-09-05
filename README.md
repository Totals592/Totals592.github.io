# Totals POS

An **offline-first, multi-tenant Point-of-Sale Progressive Web App** with a
Square-style till, full inventory management, legally-compliant VAT receipts,
and optional cloud sync — all served straight from GitHub Pages.

> **Live app:** https://totals592.github.io
> **First run:** a demo shop with products, SKUs and a supplier is created
> automatically so you can start selling immediately.
> **Demo logins:** `manager` / `1234` (full access) · `cashier` / `4321`
> (sell only). Device admin PIN for the fleet/tenant panel: **`1234`**.
> Change all of these before going live (Settings → Staff, Settings → Admin PIN).

---

## Why this shape

The app is delivered as static files on GitHub Pages. That is a feature, not a
limitation: **every push to this repo updates every installed register over the
web, with no store review and no visit to the customer.** A service worker
detects the new version, pre-caches it in the background, and shows an
"Update now" banner. That is the update mechanism you asked for.

The register works **100% offline** using a real **SQLite database compiled to
WebAssembly** (`sql.js`), persisted to IndexedDB. A cloud backend is *optional*
— point the app at one (see [`server/`](server/)) to consolidate figures across
registers and to push remote edits down to shops.

---

## Features

### Selling (Square-style, cash-only)
- Visual grid of products/services grouped by category, with colour tiles and
  photos.
- Clear cart with per-line quantity steppers and a live order summary.
- One-tap **Charge** with a cash keypad, quick-cash note buttons, exact-amount,
  and automatic change calculation.
- Hold / clear sale.

### Legal VAT receipts
Generated for an 80 mm thermal printer and printable straight from the browser.
Each receipt shows the **business name, TIN number, contact details, physical
location**, an **itemised list with quantities and prices**, the **VAT
breakdown (inclusive or exclusive)**, totals, cash tendered and change. Any past
sale can be reprinted from **Reports**.

### Barcode scanning
- **Sell screen:** a **📷 Scan** button opens the device camera to scan items
  straight into the cart (stays open for rapid multi-item scanning); each scan
  pops the item's details and price. External **USB/Bluetooth scanners** work
  too — just scan while on the Sell screen, no button needed.
- **Inventory:** **📷 Scan to add** opens the camera; a known barcode jumps to
  that product for editing, an unknown one starts a new product with the code
  pre-filled. Every variation also has a **Barcode** field for manual/scanner
  entry.
- A scanned code matches on **barcode _or_ SKU**. Uses the browser's native
  BarcodeDetector where available (Android/Chrome) and a bundled ZXing decoder
  as a fallback (iOS Safari, etc.); a manual-entry box is always offered.

### Inventory management
- Products with multiple **variations**, each carrying its own **SKU**, **barcode**, price,
  cost, stock level and **supplier**.
- **Suppliers** directory with contact details.
- **Real-time stock decrement** on every sale.
- **Low-stock thresholds** with on-tile "Low/Out" badges and a **Reorder list**
  in Reports to streamline restocking.
- Restock / stock-take dialog, CSV export.
- Upload a **product photo** (auto-downscaled to keep the local DB small).

### Multi-tenant & per-tenant login
- One install can hold many shops/tenants. Each tenant has its own products,
  suppliers, sales, currency, VAT rules, receipt branding **and staff**.
- A **login screen gates the till**: staff sign in to their shop with a username
  and PIN (PINs stored salted-and-hashed, never in plaintext). The signed-in
  name prints on receipts.
- Two roles: **Manager** (full access — inventory, suppliers, settings, staff)
  and **Cashier** (sell + reports only). Managers add/disable their own staff in
  **Settings → Staff**; the device admin can manage any shop's staff from the
  **Admin** tab. Staff sync across registers like everything else.
- The session persists across reloads; **Sign out** returns to the login screen.

### Admin control panel
- PIN-protected **Admin** tab to **create, rename, configure, suspend or
  activate** tenant accounts.
- Tenants can edit their own catalogue, prices and upload item photos.
- A matching **web control portal** ships with the backend (`/admin`) so an
  administrator can manage tenants centrally; those edits propagate to every
  register automatically on the next sync — remote management without a visit.

### Offline resilience & sync
- Durable outbox: sales, stock deltas and catalogue edits queue locally and
  upload automatically when connectivity returns (Background Sync where
  supported, plus periodic catch-up).
- Cursor-based **pull** applies remote edits (new items, price changes, tenant
  renames/suspensions) using last-write-wins.
- Status pills show online/offline and pending-sync counts.

### Data safety
- Download / restore a full **SQLite backup** from Settings; wipe local data.

---

## Project layout

```
index.html                # App shell (Sell / Inventory / Suppliers / Reports / Admin / Settings)
manifest.webmanifest      # PWA manifest (installable)
sw.js                     # Service worker: offline cache + web-delivered updates
css/app.css               # UI styles (Square-inspired)
js/
  config.js               # Money & VAT math, tenant scoping, receipt numbering
  db.js                   # SQLite-WASM + IndexedDB persistence, schema, seed data
  sync.js                 # Durable outbox → REST push + cursor pull
  receipt.js              # Legal VAT receipt generation / printing
  app.js                  # UI controller for every screen
vendor/                   # sql.js (SQLite compiled to WebAssembly) — vendored for offline
server/                   # Optional zero-dependency cloud backend + web admin portal
```

## Deploying the app

It is already a GitHub Pages site. Enable Pages for the `main` branch
(Settings → Pages) and visit `https://<user>.github.io`. To ship an update,
edit the code, **bump `APP_VERSION` in `sw.js`**, and push — installed registers
pick it up automatically.

## Deploying the backend (optional)

See [`server/README.md`](server/README.md). It is dependency-free
(`node server/server.js`) and deploys to Render/Railway/Fly/VPS unchanged. Then
set the **Cloud API base URL** in the app's Settings.

## Tech notes

- No build step, no framework, no bundler — plain HTML/CSS/JS so it is easy to
  audit and maintain.
- SQLite runs in the browser via WebAssembly; the database is the offline system
  of record.
- Everything except an (optional) live backend works with the network off.

## Scaling to many customers (Supabase + Netlify)

To host on Netlify and move the cloud database to Supabase — with real accounts
and per-tenant isolation for a multi-customer SaaS — follow
[`docs/MIGRATION-SUPABASE.md`](docs/MIGRATION-SUPABASE.md). It includes the
Postgres schema, an Edge Function implementing the app's existing sync contract,
Row-Level Security policies, and a step-by-step 2-tenant test setup.

## Roadmap

- **Delivery Tracking** — surfaced as "Coming Soon" in the app footer.
