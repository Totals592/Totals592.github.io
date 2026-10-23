# Migrating Totals POS to Supabase (hosted on GitHub Pages)

This guide takes the app from its reference-server setup to **Supabase (Postgres
database, storage, and — for production — authentication)** as the cloud backend,
while the front end stays on **GitHub Pages**, sized for a **2-tenant user test**.

> **Hosting:** the front end is served from GitHub Pages
> (`totals592.github.io`) and the backend is a **Supabase Edge Function**. This
> is the GitHub + Supabase setup used for testing. (Netlify was an earlier
> option and is no longer used — those files were removed from the repo.)

There are two milestones:

- **A. Test-ready** — get two shops running against Supabase quickly, reusing the
  app's existing sync contract. Least work; enough for user testing.
- **B. Production-hardened** — add Supabase Auth accounts + Row-Level Security so
  each customer is cryptographically isolated. Do this before real customers.

Nothing about the offline behaviour changes: each register still keeps its local
SQLite-WASM database and syncs up/down. Supabase is the cloud mirror.

---

## 0. What moves where

| Piece | Today | After migration |
|-------|-------|-----------------|
| Frontend (PWA) | GitHub Pages | **GitHub Pages** (unchanged — same static files) |
| Cloud database | `server/data.json` | **Supabase Postgres** |
| Sync API (`/api/sync`, `/api/pull`) | `server/server.js` | **Supabase Edge Function** |
| Product/logo images | base64 in the DB | (optional) **Supabase Storage** |
| Accounts / isolation | shared admin token | **Supabase Auth + RLS** (milestone B) |

The app already talks to a **configurable API base URL** (Admin → Cloud sync), so
pointing it at Supabase is mostly a settings change plus deploying one function.

---

## 1. Create the Supabase project

1. Sign up at supabase.com → **New project**. Pick a region near Guyana
   (e.g. `us-east-1`). Save the **Project URL** and the **anon** and
   **service_role** API keys (Project Settings → API).
2. Open the **SQL Editor** and run the schema in section 2.

## 2. Database schema (run in Supabase SQL Editor)

This mirrors the app's SQLite tables in Postgres. IDs stay TEXT (the app
generates them, so offline devices never collide).

```sql
create table if not exists tenants (
  id text primary key,
  name text not null,
  slug text,
  tin text,
  phone text,
  email text,
  address text,
  currency text default 'GYD',
  vat_rate numeric default 15,
  vat_inclusive int default 1,
  vat_enabled int default 1,
  vat_show_receipt int default 1,
  service_charge_enabled int default 0,
  service_charge_rate numeric default 0,
  service_charge_show_receipt int default 1,
  logo_on_receipt int default 1,
  order_no_on_receipt int default 1,
  analytics_enabled int default 0,
  remote_sales_enabled int default 1,
  import_inventory_enabled int default 0,
  expiry_tracking_enabled int default 0,
  categories text,
  receipt_footer text,
  logo text,
  status text default 'active',
  updated_at timestamptz,
  created_at timestamptz,
  seq bigserial
);

create table if not exists suppliers (
  id text primary key, tenant_id text not null references tenants(id),
  name text not null, contact text, phone text, email text, address text,
  updated_at timestamptz, created_at timestamptz, seq bigserial
);

create table if not exists products (
  id text primary key, tenant_id text not null references tenants(id),
  name text not null, description text, category text default 'General',
  image text, color text, active int default 1, sort int default 0,
  updated_at timestamptz, created_at timestamptz, seq bigserial
);

create table if not exists variations (
  id text primary key, product_id text not null references products(id),
  tenant_id text not null references tenants(id),
  name text default 'Default', sku text, barcode text,
  price numeric not null default 0, cost numeric default 0, stock numeric default 0,
  track_stock int default 1, low_stock_threshold numeric default 5,
  supplier_id text, discount_type text default 'none', discount_value numeric default 0,
  expiry_date text,
  active int default 1,
  updated_at timestamptz, created_at timestamptz, seq bigserial
);

create table if not exists staff (
  id text primary key, tenant_id text not null references tenants(id),
  name text not null, username text not null, pin_hash text, salt text,
  role text default 'cashier',
  can_view_sales int default 0, can_manage_inventory int default 0,
  active int default 1,
  updated_at timestamptz, created_at timestamptz, seq bigserial
);

create table if not exists sales (
  id text primary key, tenant_id text not null references tenants(id),
  receipt_no text, order_no int, order_date text,
  subtotal numeric, vat_amount numeric, total numeric,
  cash_received numeric, change_due numeric, item_count numeric,
  cashier text, vat_inclusive int, vat_rate numeric,
  service_charge numeric default 0, service_charge_rate numeric default 0,
  origin_device text,
  currency text, status text default 'completed', synced int default 1,
  created_at timestamptz, received_at timestamptz default now(),
  updated_at timestamptz, seq bigserial
);

create table if not exists sale_items (
  id text primary key, sale_id text not null references sales(id),
  tenant_id text not null references tenants(id),
  product_id text, variation_id text, name text, sku text,
  qty numeric, unit_price numeric, list_price numeric, line_total numeric,
  updated_at timestamptz, seq bigserial
);

-- Subscription licensing (see section "Subscription licensing" below).
create table if not exists subscriptions (
  tenant_id text primary key references tenants(id),
  plan text default 'trial', status text default 'active',
  started_at timestamptz, expires_at timestamptz, grace_until timestamptz,
  entitlements jsonb,
  updated_at timestamptz, created_at timestamptz, seq bigserial
);

create table if not exists subscription_audit_log (
  id text primary key, tenant_id text not null references tenants(id),
  action text not null, from_plan text, to_plan text,
  from_expires timestamptz, to_expires timestamptz, note text,
  at timestamptz, seq bigserial
);

-- Devices seen per tenant (visibility only — no cap enforced), recorded by
-- the license endpoint as a side effect of a check-in.
create table if not exists devices (
  device_id text primary key, tenant_id text not null references tenants(id),
  device_name text, first_seen timestamptz, last_seen timestamptz, seq bigserial
);

create index if not exists idx_sales_seq on sales(seq);
create index if not exists idx_sale_items_seq on sale_items(seq);

create index if not exists idx_var_tenant on variations(tenant_id);
create index if not exists idx_prod_tenant on products(tenant_id);
create index if not exists idx_sales_tenant on sales(tenant_id);
```

The `seq bigserial` columns give the cursor the app's `/api/pull` uses: the
function returns rows whose `seq` is greater than the register's last cursor.

### 2a. Make updates re-sync (required for voids to reach other devices)

A `bigserial` column only auto-increments on **INSERT**, never on **UPDATE**.
Without help, when one register **voids** a sale (or an admin edits a price),
the row is updated but its `seq` stays the same — so any device whose cursor is
already past that `seq` never re-downloads it and never sees the change. That is
exactly why a void on one device didn't appear on another.

The fix is a tiny trigger that bumps `seq` to a fresh value on every UPDATE, so
the changed row jumps ahead of every register's cursor and is pulled again. Run
this once in the SQL Editor:

```sql
create or replace function bump_seq() returns trigger
language plpgsql as $$
begin
  new.seq := nextval(pg_get_serial_sequence(tg_table_name, 'seq'));
  return new;
end $$;

do $$
declare t text;
begin
  foreach t in array array['tenants','products','variations','staff','sales','sale_items','subscriptions','devices']
  loop
    execute format('drop trigger if exists %I_bump_seq on %I', t, t);
    execute format('create trigger %I_bump_seq before update on %I
                    for each row execute function bump_seq()', t, t);
  end loop;
end $$;
```

After this, voiding a sale on register A propagates to register B on its next
sync, and remote catalogue/price edits always re-download too.

### 2b. Already have the tables? Add the new columns

If your project was created before these features, add the new columns (safe to
re-run — `if not exists` guards each one), then run 2a:

```sql
alter table variations add column if not exists expiry_date text;
alter table sale_items add column if not exists list_price numeric;
alter table staff      add column if not exists can_view_sales int default 0;
alter table staff      add column if not exists can_manage_inventory int default 0;
alter table tenants    add column if not exists import_inventory_enabled int default 0;
alter table tenants    add column if not exists expiry_tracking_enabled int default 0;

-- If you don't have these tables yet (added for subscription licensing),
-- run the three `create table if not exists` statements for subscriptions,
-- subscription_audit_log and devices from section 2 above, then re-run 2a
-- (the bump_seq trigger loop now also covers 'subscriptions' and 'devices').
```

### 2c. Per-shop security, sign-ups and login lockout

Each shop's devices may only download and change that shop's data; the
owner's devices hold an **admin key** and see everything. These tables back
the sign-up requests and the wrong-PIN lockout, and Row-Level Security (with
no policies) blocks every direct database client — only the Edge Function
(which uses the service-role key) can read or write. Safe to re-run.

```sql
create table if not exists signup_requests (
  id text primary key, status text default 'pending',
  owner_name text, shop_name text, phone text, phone2 text, email text, address text,
  currency text, username text, pin_hash text, salt text,
  tenant_id text, note text, created_at timestamptz default now(), decided_at timestamptz
);

create table if not exists login_failures (
  key text primary key, count int default 0, locked_until timestamptz, updated_at timestamptz
);

do $$
declare t text;
begin
  foreach t in array array['tenants','suppliers','products','variations','staff','sales','sale_items',
                           'subscriptions','subscription_audit_log','devices','signup_requests','login_failures']
  loop
    if to_regclass('public.' || t) is not null then
      execute format('alter table public.%I enable row level security', t);
    end if;
  end loop;
end $$;
```

## 3. The sync API — Supabase Edge Function

You need one small server that implements `/api/sync` and `/api/pull` against
Supabase. On the GitHub + Supabase setup this is a **Supabase Edge Function**
named `api`. (This is already deployed for the live project; the code is here so
you can review or redeploy it.)

Create `supabase/functions/api/index.ts`:

```ts
import { serve } from "https://deno.land/std/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const db = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!  // server-side only
);
const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "content-type, authorization, x-admin-key, x-device-token",
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
};
const json = (b: unknown, s = 200) =>
  new Response(JSON.stringify(b), { status: s, headers: { ...cors, "content-type": "application/json" } });
const nowISO = () => new Date().toISOString();
const enc = new TextEncoder();

/* ---------------- Subscription license signing (ECDSA P-256 / ES256) ----
 * The PRIVATE key lives only here (a Supabase secret); js/config.js in the
 * app embeds the matching PUBLIC key to verify tokens fully offline. */
const GRACE_DAYS = 5;
let _licenseKeyPromise: Promise<CryptoKey> | null = null;
function b64urlToBytes(s: string): Uint8Array {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}
function bytesToB64url(bytes: ArrayBuffer | Uint8Array): string {
  return btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function licenseKeyB64(): string {
  const b64 = Deno.env.get("LICENSE_PRIVATE_KEY_PKCS8_B64");
  if (!b64) throw new Error("LICENSE_PRIVATE_KEY_PKCS8_B64 is not set");
  return b64;
}
function getLicensePrivateKey(): Promise<CryptoKey> {
  if (!_licenseKeyPromise) {
    // STANDARD base64 (not base64url) — do not run through b64urlToBytes.
    const raw = Uint8Array.from(atob(licenseKeyB64()), (c) => c.charCodeAt(0));
    _licenseKeyPromise = crypto.subtle.importKey(
      "pkcs8", raw, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]
    );
  }
  return _licenseKeyPromise;
}
async function signLicenseToken(payload: Record<string, unknown>): Promise<string> {
  const key = await getLicensePrivateKey();
  const h = bytesToB64url(enc.encode(JSON.stringify({ alg: "ES256", typ: "LICENSE" })));
  const p = bytesToB64url(enc.encode(JSON.stringify(payload)));
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, enc.encode(h + "." + p));
  return h + "." + p + "." + bytesToB64url(sig);
}
const FULL_ACCESS = { analytics: true, remote_sales: true, import_inventory: true, expiry_tracking: true };
// Look up (creating a default 3-day full-access trial if none exists yet, so
// a brand-new shop is immediately usable) and sign a license for a tenant.
async function issueLicense(tenantId: string): Promise<string> {
  let { data: sub } = await db.from("subscriptions").select("*").eq("tenant_id", tenantId).maybeSingle();
  if (!sub) sub = await createTrial(tenantId, "auto-issued 3-day trial");
  return signLicenseToken({
    tenant_id: tenantId, plan: sub.plan, canceled: sub.status === "canceled",
    expires_at: sub.expires_at, grace_until: sub.grace_until,
    entitlements: sub.entitlements || {}, issued_at: nowISO()
  });
}
async function createTrial(tenantId: string, note: string) {
  const now = new Date();
  const expires = new Date(now.getTime() + 3 * 86400000);
  const grace = new Date(expires.getTime() + GRACE_DAYS * 86400000);
  const sub = {
    tenant_id: tenantId, plan: "trial", status: "active",
    started_at: now.toISOString(), expires_at: expires.toISOString(), grace_until: grace.toISOString(),
    entitlements: FULL_ACCESS, created_at: now.toISOString(), updated_at: now.toISOString()
  };
  await db.from("subscriptions").upsert(sub);
  await db.from("subscription_audit_log").insert({
    id: crypto.randomUUID(), tenant_id: tenantId, action: "created", to_plan: "trial",
    to_expires: sub.expires_at, note, at: now.toISOString()
  });
  return sub;
}

/* ---------------- Device auth & per-shop scoping ------------------------
 * X-Admin-Key: <ADMIN_KEY secret>  -> the owner's device: every shop.
 * X-Device-Token: <token>          -> ONE shop, issued by /login after a
 *                                     staff shop-name + username + PIN check.
 * Tokens are HMAC-signed with a key derived from the license private key, so
 * no extra secret is needed for them. */
let _hmacKey: Promise<CryptoKey> | null = null;
function hmacKey(): Promise<CryptoKey> {
  if (!_hmacKey) {
    _hmacKey = crypto.subtle.digest("SHA-256", enc.encode("device-token-v1:" + licenseKeyB64()))
      .then((raw) => crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]));
  }
  return _hmacKey;
}
async function signDeviceToken(payload: Record<string, unknown>): Promise<string> {
  const p = bytesToB64url(enc.encode(JSON.stringify(payload)));
  const mac = await crypto.subtle.sign("HMAC", await hmacKey(), enc.encode(p));
  return p + "." + bytesToB64url(mac);
}
async function verifyDeviceToken(tok: string): Promise<{ tid: string; sid: string } | null> {
  const parts = String(tok || "").split(".");
  if (parts.length !== 2) return null;
  try {
    const ok = await crypto.subtle.verify("HMAC", await hmacKey(), b64urlToBytes(parts[1]), enc.encode(parts[0]));
    if (!ok) return null;
    return JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[0])));
  } catch (_) { return null; }
}
function safeEqual(a: string, b: string): boolean {
  if (!a || !b || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
type Auth = { scope: "admin" } | { scope: "tenant"; tid: string; sid: string } | { error: string };
async function authenticate(req: Request): Promise<Auth> {
  const key = req.headers.get("x-admin-key");
  if (key) return safeEqual(key, Deno.env.get("ADMIN_KEY") || "") ? { scope: "admin" } : { error: "bad_admin_key" };
  const tok = req.headers.get("x-device-token");
  if (!tok) return { error: "no_credentials" };
  const t = await verifyDeviceToken(tok);
  if (!t || !t.tid || !t.sid) return { error: "invalid_token" };
  const { data: staff } = await db.from("staff").select("tenant_id, active").eq("id", t.sid).maybeSingle();
  const { data: tenant } = await db.from("tenants").select("status").eq("id", t.tid).maybeSingle();
  // Revoked when the staff member is removed/deactivated or the shop deleted.
  if (!staff || staff.tenant_id !== t.tid || !Number(staff.active ?? 1) || !tenant || tenant.status === "deleted") {
    return { error: "revoked" };
  }
  return { scope: "tenant", tid: t.tid, sid: t.sid };
}
const norm = (s: unknown) => String(s ?? "").trim().replace(/\s+/g, " ").toLowerCase();
async function shopNameTaken(name: string, exceptTenantId?: string | null): Promise<boolean> {
  const { data } = await db.from("tenants").select("id, name").neq("status", "deleted");
  return (data || []).some((t: { id: string; name: string }) => t.id !== exceptTenantId && norm(t.name) === norm(name));
}
// The tenant id that owns a row (null when the row doesn't exist yet).
async function ownerOf(table: string, id: string): Promise<string | null> {
  if (!id) return null;
  const { data } = await db.from(table).select("tenant_id").eq("id", id).maybeSingle();
  return data ? data.tenant_id : null;
}
// Shop settings a manager may change from their own device; plan/feature
// switches, currency and status stay with the admin.
const ADMIN_ONLY_TENANT_FIELDS = ["status", "currency", "analytics_enabled", "remote_sales_enabled",
  "import_inventory_enabled", "expiry_tracking_enabled"];
// Decide whether a shop-scoped device may apply this change (pinning its
// payload to that shop). Admin devices may apply anything.
// deno-lint-ignore no-explicit-any
async function authorizeChange(ch: any, auth: Auth): Promise<boolean> {
  if ("error" in auth) return false;
  if (auth.scope === "admin") return true;
  const tid = auth.tid;
  const p = ch.payload || (ch.payload = {});
  const mine = async (table: string, id: string) => { const o = await ownerOf(table, id); return o === null || o === tid; };
  switch (ch.entity) {
    case "tenant": {
      if (ch.entity_id !== tid) return false;
      ADMIN_ONLY_TENANT_FIELDS.forEach((f) => delete p[f]);
      if (p.name != null && await shopNameTaken(p.name, tid)) delete p.name;
      return true;
    }
    case "product": {
      if (ch.op === "delete") return (await ownerOf("products", ch.entity_id)) === tid;
      if (p.product) { if (!(await mine("products", p.product.id))) return false; p.product.tenant_id = tid; }
      for (const v of p.variations || []) {
        if (!(await mine("variations", v.id)) || !(await mine("products", v.product_id))) return false;
        v.tenant_id = tid;
      }
      return true;
    }
    case "staff":
      if (!(await mine("staff", ch.entity_id))) return false;
      p.tenant_id = tid; return true;
    case "stock":
      return (await ownerOf("variations", ch.entity_id)) === tid;
    case "sale": {
      if (!(await mine("sales", ch.entity_id))) return false;
      if (p.sale) p.sale.tenant_id = tid;
      for (const it of p.items || []) {
        if (it.id && !(await mine("sale_items", it.id))) return false;
        it.tenant_id = tid;
      }
      return true;
    }
    default: return false; // subscriptions etc. are admin-only
  }
}

/* ---------------- Sign-in & sign-up ------------------------------------- */
const LOCK_AFTER = 8, LOCK_MS = 15 * 60 * 1000;
async function hashPin(pin: string, salt: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", enc.encode(String(salt) + ":" + String(pin)));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function recordDevice(deviceId: string | null, tid: string, name: string | null) {
  if (!deviceId) return;
  const now = nowISO();
  const { data: existing } = await db.from("devices").select("device_id").eq("device_id", deviceId).maybeSingle();
  // first_seen only on the very first check-in (omitting the key leaves it).
  await db.from("devices").upsert({
    device_id: deviceId, tenant_id: tid, device_name: name,
    ...(existing ? {} : { first_seen: now }), last_seen: now
  });
}
// deno-lint-ignore no-explicit-any
async function notifySignup(r: any) {
  const key = Deno.env.get("RESEND_API_KEY"), to = Deno.env.get("NOTIFY_EMAIL");
  if (!key || !to) return;
  const text = [
    "A new shop asked to join TS - POS:", "",
    "Shop: " + r.shop_name, "Owner: " + r.owner_name, "Phone: " + r.phone,
    "Second phone: " + (r.phone2 || "-"), "Email: " + (r.email || "-"),
    "Location: " + (r.address || "-"), "Currency: " + r.currency, "Username: " + r.username, "",
    "Approve it in the app: Admin -> Sign-up requests."
  ].join("\n");
  try {
    await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: "Bearer " + key, "Content-Type": "application/json" },
      body: JSON.stringify({
        from: Deno.env.get("NOTIFY_FROM") || "TS - POS <onboarding@resend.dev>",
        to: [to], subject: "New TS - POS sign-up: " + r.shop_name, text
      })
    });
  } catch (e) { console.error("signup e-mail failed", e); }
}
const CURRENCIES = ["GYD", "USD", "EUR", "GBP", "GHS", "NGN", "KES", "ZAR"];
// deno-lint-ignore no-explicit-any
function validateSignup(b: any): string | null {
  const str = (v: unknown, max: number) => typeof v === "string" && v.trim().length > 0 && v.length <= max;
  if (!str(b.owner_name, 80)) return "Enter your name.";
  if (!str(b.shop_name, 80) || b.shop_name.trim().length < 2) return "Enter your shop name.";
  if (!/^[0-9+()\-\s]{7,20}$/.test(String(b.phone || ""))) return "Enter a valid phone number.";
  if (b.phone2 && !/^[0-9+()\-\s]{7,20}$/.test(String(b.phone2))) return "Enter a valid second phone number.";
  if (b.email && !/^[^\s@]{1,64}@[^\s@]{1,100}\.[^\s@]{2,}$/.test(String(b.email))) return "Enter a valid email address.";
  if (!str(b.address, 200)) return "Enter your shop location.";
  if (!CURRENCIES.includes(b.currency)) return "Choose a currency.";
  if (!/^[a-z0-9._-]{2,30}$/.test(String(b.username || ""))) return "Username: 2-30 letters or numbers.";
  if (!/^[0-9a-f]{64}$/.test(String(b.pin_hash || "")) || !/^[0-9a-f]{8,64}$/.test(String(b.salt || ""))) return "Invalid PIN.";
  return null;
}
const slugify = (s: string) => norm(s).replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 40);

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  const url = new URL(req.url);
  const path = url.pathname.replace(/^.*\/api/, "");   // "/sync", "/pull", ...

  // ---- Staff sign-in -> shop-scoped device token (public) ----
  if (path === "/login" && req.method === "POST") {
    const b = await req.json().catch(() => ({}));
    const shop = norm(b.shop), user = norm(b.username);
    if (!shop || !user || !b.pin) return json({ error: "missing_fields" }, 400);
    const key = shop + "|" + user;
    const { data: f } = await db.from("login_failures").select("*").eq("key", key).maybeSingle();
    if (f && f.locked_until && new Date(f.locked_until) > new Date()) {
      return json({ error: "locked", retry_after: f.locked_until }, 429);
    }
    const { data: tenants } = await db.from("tenants").select("id, name, status").neq("status", "deleted");
    const tenant = (tenants || []).find((t: { name: string }) => norm(t.name) === shop);
    let staff = null;
    if (tenant) {
      const { data: rows } = await db.from("staff").select("*").eq("tenant_id", tenant.id);
      staff = (rows || []).find((s: { username: string; active: number }) => norm(s.username) === user && Number(s.active ?? 1)) || null;
    }
    if (!tenant || !staff || (await hashPin(b.pin, staff.salt)) !== staff.pin_hash) {
      let count = (f ? f.count : 0) + 1, locked_until = null;
      if (count >= LOCK_AFTER) { locked_until = new Date(Date.now() + LOCK_MS).toISOString(); count = 0; }
      await db.from("login_failures").upsert({ key, count, locked_until, updated_at: nowISO() });
      return json({ error: "invalid_login" }, 401);
    }
    if (tenant.status === "suspended") return json({ error: "suspended" }, 403);
    if (f) await db.from("login_failures").delete().eq("key", key);
    await recordDevice(b.device_id || null, tenant.id, b.device_name || null);
    const token = await signDeviceToken({ tid: tenant.id, sid: staff.id, iat: nowISO() });
    return json({ token, tenant_id: tenant.id, tenant_name: tenant.name });
  }

  // ---- Public sign-up request (owner approves it in Admin) ----
  if (path === "/signup" && req.method === "POST") {
    const b = await req.json().catch(() => ({}));
    if (b.website) return json({ ok: true });   // honeypot: bots fill hidden fields
    const bad = validateSignup(b);
    if (bad) return json({ error: "invalid", message: bad }, 400);
    const { data: pending } = await db.from("signup_requests").select("shop_name, phone").eq("status", "pending");
    const list = pending || [];
    if (list.length >= 500) return json({ error: "busy", message: "Too many pending requests — please call us." }, 429);
    if (list.filter((r: { phone: string }) => r.phone === b.phone.trim()).length >= 3) {
      return json({ error: "busy", message: "You already have requests waiting — we will contact you soon." }, 429);
    }
    if (await shopNameTaken(b.shop_name) || list.some((r: { shop_name: string }) => norm(r.shop_name) === norm(b.shop_name))) {
      return json({ error: "shop_taken", message: "That shop name is already registered. Please choose another." }, 409);
    }
    // deno-lint-ignore no-explicit-any
    const r: any = { id: "sup_" + crypto.randomUUID(), status: "pending", created_at: nowISO() };
    ["owner_name", "shop_name", "phone", "phone2", "email", "address", "currency", "username", "pin_hash", "salt"]
      .forEach((k) => { r[k] = typeof b[k] === "string" && b[k].trim() ? b[k].trim() : null; });
    r.username = r.username.toLowerCase();
    const { error } = await db.from("signup_requests").insert(r);
    if (error) return json({ error: "failed", message: "Could not save your request — please try again." }, 500);
    await notifySignup(r);
    return json({ ok: true });
  }

  // Everything below needs a device token or the admin key.
  const auth = await authenticate(req);
  if ("error" in auth) return json({ error: auth.error }, 401);
  const tid = auth.scope === "tenant" ? auth.tid : null;

  if (path === "/whoami" && req.method === "GET") return json({ scope: auth.scope, tenant_id: tid });

  if (path === "/shop-name-available" && req.method === "GET") {
    const name = url.searchParams.get("name") || "";
    return json({ available: !!name.trim() && !(await shopNameTaken(name, tid || url.searchParams.get("tenant_id"))) });
  }

  // ---- Sign-up review (admin only) ----
  if (path.startsWith("/signups")) {
    if (auth.scope !== "admin") return json({ error: "admin_only" }, 403);
    if (path === "/signups" && req.method === "GET") {
      const { data } = await db.from("signup_requests")
        .select("id, status, owner_name, shop_name, phone, phone2, email, address, currency, username, tenant_id, created_at, decided_at, note")
        .order("created_at", { ascending: false }).limit(100);
      return json({ requests: data || [] });
    }
    const b = await req.json().catch(() => ({}));
    const { data: r } = await db.from("signup_requests").select("*").eq("id", b.id).maybeSingle();
    if (!r || r.status !== "pending") return json({ error: "not_found" }, 404);
    if (path === "/signups/approve" && req.method === "POST") {
      if (await shopNameTaken(r.shop_name)) return json({ error: "shop_taken", message: "A shop with this name already exists." }, 409);
      const now = nowISO();
      const newTid = "ten_" + crypto.randomUUID();
      await db.from("tenants").insert({
        id: newTid, name: r.shop_name, slug: slugify(r.shop_name), phone: r.phone, email: r.email,
        address: r.address, currency: r.currency, status: "active", created_at: now, updated_at: now
      });
      await db.from("staff").insert({
        id: "stf_" + crypto.randomUUID(), tenant_id: newTid, name: r.owner_name, username: r.username,
        pin_hash: r.pin_hash, salt: r.salt, role: "manager", active: 1, created_at: now, updated_at: now
      });
      await createTrial(newTid, "Sign-up approved — 3-day trial");
      await db.from("signup_requests").update({ status: "approved", tenant_id: newTid, decided_at: now }).eq("id", r.id);
      return json({ ok: true, tenant_id: newTid });
    }
    if (path === "/signups/reject" && req.method === "POST") {
      await db.from("signup_requests").update({ status: "rejected", decided_at: nowISO(), note: b.note || null }).eq("id", r.id);
      return json({ ok: true });
    }
    return json({ error: "not found" }, 404);
  }

  // PUSH: registers upload their outbox; each change is checked against the
  // device's shop first.
  if (path === "/sync" && req.method === "POST") {
    const { changes = [] } = await req.json();
    const applied: string[] = [], rejected: string[] = [];
    for (const ch of changes) {
      try {
        if (!(await authorizeChange(ch, auth))) { rejected.push(ch.id); continue; }
        const p = ch.payload || {};
        if (ch.entity === "tenant")  await db.from("tenants").upsert({ id: ch.entity_id, ...p });
        else if (ch.entity === "product") {
          if (ch.op === "delete") await db.from("products").update({ active: 0, updated_at: nowISO() }).eq("id", ch.entity_id);
          if (p.product) await db.from("products").upsert(p.product);
          if (p.variations) for (const v of p.variations) await db.from("variations").upsert(v);
        }
        else if (ch.entity === "staff") await db.from("staff").upsert({ id: ch.entity_id, ...p });
        else if (ch.entity === "stock") {
          const { data } = await db.from("variations").select("stock").eq("id", ch.entity_id).single();
          const cur = Number(data?.stock ?? 0);
          const next = ch.op === "set" ? Number(p.stock || 0) : cur - Number(p.qty || 0);
          await db.from("variations").update({ stock: next, updated_at: nowISO() }).eq("id", ch.entity_id);
        }
        else if (ch.entity === "sale") {
          if (p.sale) await db.from("sales").upsert(p.sale);
          // Use the client's item id (falls back to a uuid) so replays don't duplicate lines.
          if (p.items) for (const it of p.items)
            await db.from("sale_items").upsert({ id: it.id || crypto.randomUUID(), sale_id: ch.entity_id, ...it });
        }
        else if (ch.entity === "subscription") await db.from("subscriptions").upsert({ tenant_id: ch.entity_id, ...p });
        else if (ch.entity === "subscription_audit") await db.from("subscription_audit_log").upsert({ id: ch.entity_id, ...p });
        applied.push(ch.id);
      } catch (_) { /* leave un-applied; the register retries */ }
    }
    return json({ applied, rejected });
  }

  // PULL: rows changed since each per-table cursor — only the device's own
  // shop unless it holds the admin key.
  if (path === "/pull" && req.method === "GET") {
    const qp = url.searchParams;
    const legacy = Number(qp.get("since") || 0);
    const cur = (name: string) => Number(qp.get(name + "_since") ?? legacy) || 0;
    const pick = async (t: string, col = "tenant_id") => {
      let q = db.from(t).select("*").gt("seq", cur(t));
      if (tid) q = q.eq(col, tid);
      return (await q.order("seq")).data || [];
    };
    const tenants = await pick("tenants", "id");
    const products = await pick("products");
    const variations = await pick("variations");
    const staff = await pick("staff");
    const sales = await pick("sales");
    const sale_items = await pick("sale_items");
    const subscriptions = await pick("subscriptions");
    const subscription_audit_log = await pick("subscription_audit_log");
    const devices = await pick("devices");
    return json({ tenants, products, variations, staff, sales, sale_items, subscriptions, subscription_audit_log, devices });
  }

  // LICENSE: sign a fresh token for a tenant's current subscription state,
  // and record the requesting device (visibility only, no cap enforced).
  if (path === "/license" && req.method === "GET") {
    const t = url.searchParams.get("tenant_id");
    if (!t) return json({ error: "tenant_id required" }, 400);
    if (tid && t !== tid) return json({ error: "wrong_shop" }, 403);
    await recordDevice(url.searchParams.get("device_id"), t, url.searchParams.get("device_name"));
    try {
      return json({ token: await issueLicense(t) });
    } catch (e) {
      return json({ error: String((e as Error).message || e) }, 500);
    }
  }

  return json({ error: "not found" }, 404);
});
```

Deploy it with the Supabase CLI:

```bash
npm i -g supabase
supabase login
supabase link --project-ref <your-project-ref>
supabase functions deploy api --no-verify-jwt   # test milestone; add JWT for prod
```

The function's own URL is `https://<project-ref>.functions.supabase.co/api`, but
in the **app** set the Cloud API base URL to the domain only —
`https://<project-ref>.functions.supabase.co` — because the app appends
`/api/sync` and `/api/pull` itself. Name the function `api` and turn its
**Verify JWT** setting OFF for the test milestone.

### 3a. Subscription licensing — one-time key setup

The subscription system (Admin → Subscription, per-shop plan/expiry/grace)
proves a device's license with a **signed token** (ECDSA P-256 / ES256) rather
than a plain database flag, so it can't be unlocked by editing local data —
only someone holding the private key can produce a token that verifies.

- The **public** key is already embedded in the app (`js/config.js`,
  `LICENSE_PUBLIC_KEY_SPKI_B64`) — safe to ship, it can only verify, never sign.
- The **private** key must never appear in this repo, the app, or any commit.
  It lives only as a Supabase secret, read solely inside the Edge Function.

Set the matching private key (generated once for this app; keep it only here):

```bash
supabase secrets set LICENSE_PRIVATE_KEY_PKCS8_B64="<the private key value your admin has>" --project-ref <your-project-ref>
supabase functions deploy api --no-verify-jwt
```

(If you don't have the private key value, or ever suspect it's leaked, a new
keypair can be generated — but the embedded public key in `js/config.js` would
need updating and redeploying to match, or every device's cached license stops
verifying. Don't rotate it without also shipping the new public key.)

**Quick check it worked:** Admin → unlock → open a tenant's **Subscription**
button → set a plan (e.g. Extra, 6 months) → Save. It syncs and fetches a
license automatically; **Settings → Subscription** on that shop's register
should show the plan, status "Active", and matching dates within a few
seconds (once online). If it instead stays on "No subscription information
cached yet", check the Edge Function logs (Supabase Dashboard → Edge
Functions → api → Logs) for a `LICENSE_PRIVATE_KEY_PKCS8_B64 is not set` error.

### 3b. Admin key and sign-up e-mails

Add these under **Edge Functions → Secrets**:

| Secret | Value |
|---|---|
| `ADMIN_KEY` | A long password only you know (20+ characters). Save it once in the app on **your** devices: Admin → Cloud sync → Admin key. Those devices sync every shop and can approve sign-ups. |
| `RESEND_API_KEY` | *(optional)* An API key from [resend.com](https://resend.com) — e-mails you each new sign-up. |
| `NOTIFY_EMAIL` | *(optional)* The address to notify — use the e-mail you signed up to Resend with. |
| `NOTIFY_FROM` | *(optional)* Sender, once you've verified your domain in Resend, e.g. `TS - POS <signups@ts-innovate.com>`. Without it, Resend's test sender is used, which can only deliver to your own Resend account address. |

Shop devices get their per-shop pass automatically when a staff member signs
in online. A device that was signed in before this change shows **"Tap to
connect cloud"** at the top — tap it and enter the PIN once.

## 4. Point the app at the sync API

The app already ships with this URL baked in (Admin → Cloud sync shows it), so on
the live site there is nothing to set. If you ever need to set it by hand —
**Admin → unlock → Cloud sync → Cloud API base URL**, then Save → Sync now — use
the Edge Function domain **without** `/api`:
`https://<project-ref>.functions.supabase.co` (the app adds `/api/sync` and
`/api/pull` itself; including `/api` here would double it to `/api/api/sync`).
This assumes the function is named `api`.

Each register now pushes sales/stock and pulls catalogue/tenant/staff changes
from Supabase.

## 5. Host the frontend on GitHub Pages

The front end is already hosted on GitHub Pages — the repo's
`.github/workflows/pages.yml` redeploys `totals592.github.io` on every push to
`main`. There is nothing extra to set up: push to `main` and Pages rebuilds. The
service worker then delivers the in-app "Update available" banner to installed
registers.

(A custom sub-domain can be added later via **Settings → Pages → Custom domain**
plus a `CNAME` file, once testing is done.)

## 6. Set up the two test tenants

1. Open `https://totals592.github.io`, go to **Admin** (PIN `1234` — change it),
   create the two shops (**+ New tenant**), each with name, TIN, currency **GYD**, VAT rate.
2. For each tenant, **Staff** → add a manager and a cashier with their own PINs.
3. Sign in per shop and add a few products (or **📷 Scan to add**).
4. Confirm sales on register A appear in Supabase (Table Editor → `sales`) and
   that editing a price in the Admin/server pulls down to register B.

That is enough for a 2-tenant user test.

---

## B. How shops are kept apart

- A shop device only holds a **device token** for its own shop, issued by
  `/api/login` after a staff member's shop name + username + PIN check (8 wrong
  PINs lock that login for 15 minutes). `/api/pull` filters every table to that
  shop, and `/api/sync` refuses any change that touches another shop, plan
  or subscription data, currency, or feature switches.
- The owner's devices send the `ADMIN_KEY` instead and see every shop.
- Row-Level Security is on with no policies, so the Supabase REST API (anon
  key) can't read anything; only the Edge Function's service role can.

Still worth doing as you grow:

- Make stock decrements a Postgres RPC (a single `update ... set stock = stock -
  qty`) so concurrent registers can't oversell.
- Move product/logo images to **Supabase Storage** instead of base64.

---

## Rollback / safety

- The local `.sqlite` backup (Settings → Backup) is always a full snapshot; keep
  one before switching the API base.
- Clearing the API base returns any register to standalone offline mode.
- Supabase keeps automatic backups; the `service_role` key must live only in the
  Edge Function's secrets, never in the frontend.
