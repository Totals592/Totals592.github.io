# Migrating Totals POS to Supabase + Netlify

This guide takes the app from its GitHub Pages + reference-server setup to
**Netlify (frontend hosting)** and **Supabase (Postgres database, storage, and —
for production — authentication)**, sized for a **2-tenant user test**.

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
| Frontend (PWA) | GitHub Pages | **Netlify** (same static files) |
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
  supplier_id text, active int default 1,
  updated_at timestamptz, created_at timestamptz, seq bigserial
);

create table if not exists staff (
  id text primary key, tenant_id text not null references tenants(id),
  name text not null, username text not null, pin_hash text, salt text,
  role text default 'cashier', active int default 1,
  updated_at timestamptz, created_at timestamptz, seq bigserial
);

create table if not exists sales (
  id text primary key, tenant_id text not null references tenants(id),
  receipt_no text, order_no int, order_date text,
  subtotal numeric, vat_amount numeric, total numeric,
  cash_received numeric, change_due numeric, item_count numeric,
  cashier text, vat_inclusive int, vat_rate numeric,
  service_charge numeric default 0, service_charge_rate numeric default 0,
  currency text, status text default 'completed', synced int default 1,
  created_at timestamptz, received_at timestamptz default now()
);

create table if not exists sale_items (
  id text primary key, sale_id text not null references sales(id),
  tenant_id text not null references tenants(id),
  product_id text, variation_id text, name text, sku text,
  qty numeric, unit_price numeric, line_total numeric
);

create index if not exists idx_var_tenant on variations(tenant_id);
create index if not exists idx_prod_tenant on products(tenant_id);
create index if not exists idx_sales_tenant on sales(tenant_id);
```

The `seq bigserial` columns give the cursor the app's `/api/pull` uses: the
function returns rows whose `seq` is greater than the register's last cursor.

## 3. The sync API

You need one small server that implements `/api/sync` and `/api/pull` against
Supabase. **Recommended path (no CLI, no Edge-Function UI): run it as a Netlify
Function — it already ships in this repo.**

### 3A. Recommended — Netlify Function (already in the repo)

The repo contains `netlify/functions/api.mjs`, `netlify.toml`, and a root
`package.json`. When you connect this repo to Netlify (section 5), Netlify builds
and hosts the function automatically and maps `/api/*` to it. There is nothing to
paste or deploy by hand — you only set two environment variables in Netlify:

| Netlify env var | Where to get it |
|-----------------|-----------------|
| `SUPABASE_URL` | Supabase → Project Settings → API → Project URL |
| `SUPABASE_SERVICE_ROLE_KEY` | Supabase → Project Settings → API → **service_role** key (secret) |

Set them under **Netlify → Site configuration → Environment variables**, then
redeploy. Your API base URL is simply **your Netlify site URL** (e.g.
`https://your-site.netlify.app`) — the app appends `/api/sync` and `/api/pull`.
The service-role key stays on Netlify's servers and is never sent to browsers.

Skip to section 4. (Section 3B below is only if you prefer Supabase Edge
Functions instead — you do not need both.)

### 3B. Alternative — Supabase Edge Function (needs the Supabase CLI)

This implements the SAME contract. Create `supabase/functions/api/index.ts`:

```ts
import { serve } from "https://deno.land/std/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const db = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!  // server-side only
);
const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "content-type, authorization",
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
};
const json = (b: unknown, s = 200) =>
  new Response(JSON.stringify(b), { status: s, headers: { ...cors, "content-type": "application/json" } });

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  const url = new URL(req.url);

  // PUSH: registers upload their outbox.
  if (url.pathname.endsWith("/sync") && req.method === "POST") {
    const { changes = [] } = await req.json();
    const applied: string[] = [];
    for (const ch of changes) {
      try {
        const p = ch.payload || {};
        if (ch.entity === "tenant")  await db.from("tenants").upsert({ id: ch.entity_id, ...p });
        else if (ch.entity === "product") {
          if (p.product) await db.from("products").upsert(p.product);
          if (p.variations) for (const v of p.variations) await db.from("variations").upsert(v);
        }
        else if (ch.entity === "staff") await db.from("staff").upsert({ id: ch.entity_id, ...p });
        else if (ch.entity === "stock") {
          const { data } = await db.from("variations").select("stock").eq("id", ch.entity_id).single();
          const cur = Number(data?.stock ?? 0);
          const next = ch.op === "set" ? Number(p.stock || 0) : cur - Number(p.qty || 0);
          await db.from("variations").update({ stock: next, updated_at: new Date().toISOString() }).eq("id", ch.entity_id);
        }
        else if (ch.entity === "sale") {
          if (p.sale) await db.from("sales").upsert(p.sale);
          if (p.items) for (const it of p.items)
            await db.from("sale_items").upsert({ id: crypto.randomUUID(), sale_id: ch.entity_id, ...it });
        }
        applied.push(ch.id);
      } catch (_) { /* leave un-applied; the register retries */ }
    }
    return json({ applied });
  }

  // PULL: registers download rows changed since their cursor.
  if (url.pathname.endsWith("/pull") && req.method === "GET") {
    const since = Number(url.searchParams.get("since") || 0);
    const pick = async (t: string) =>
      (await db.from(t).select("*").gt("seq", since).order("seq")).data || [];
    const tenants = await pick("tenants");
    const products = await pick("products");
    const variations = await pick("variations");
    const staff = await pick("staff");
    const maxSeq = [...tenants, ...products, ...variations, ...staff]
      .reduce((m, r: any) => Math.max(m, r.seq || 0), since);
    return json({ cursor: maxSeq, tenants, products, variations, staff });
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

## 4. Point the app at the sync API

In the running app: **Admin → unlock → Cloud sync → Cloud API base URL**, then
Save → Sync now:

- **Netlify Function path (3A):** use your **Netlify site URL**, e.g.
  `https://your-site.netlify.app`
- **Edge Function path (3B):** use the domain **without** `/api` —
  `https://<project-ref>.functions.supabase.co` (the app adds `/api/sync`
  itself; including `/api` here would double it to `/api/api/sync`). This assumes
  the function is named `api`.

Each register now pushes sales/stock and pulls catalogue/tenant/staff changes
from Supabase. (`/api/sync` and `/api/pull` are appended by the app.)

## 5. Deploy the frontend to Netlify

1. netlify.com → **Add new site → Import from Git** → pick this repo.
2. Build command: *none*. Publish directory: `/` (root — it's static).
3. Deploy. Netlify gives you `https://<name>.netlify.app`. Every push to `main`
   redeploys automatically (same as the Pages workflow does now).

The service worker still delivers in-app updates on top of that.

## 6. Set up the two test tenants

1. Open the Netlify URL, go to **Admin** (PIN `1234` — change it), create the two
   shops (**+ New tenant**), each with name, TIN, currency **GYD**, VAT rate.
2. For each tenant, **Staff** → add a manager and a cashier with their own PINs.
3. Sign in per shop and add a few products (or **📷 Scan to add**).
4. Confirm sales on register A appear in Supabase (Table Editor → `sales`) and
   that editing a price in the Admin/server pulls down to register B.

That is enough for a 2-tenant user test.

---

## B. Hardening for real accounts (before paying customers)

For genuinely separate customer accounts you must add authentication and
Row-Level Security so one tenant can never read another's rows.

```sql
-- Who may touch which tenant.
create table memberships (
  user_id uuid references auth.users(id),
  tenant_id text references tenants(id),
  role text default 'manager',
  primary key (user_id, tenant_id)
);

-- Turn on RLS everywhere.
alter table tenants     enable row level security;
alter table products    enable row level security;
alter table variations  enable row level security;
alter table suppliers   enable row level security;
alter table sales       enable row level security;
alter table sale_items  enable row level security;
alter table staff       enable row level security;

-- A helper: tenants the current user belongs to.
create or replace function my_tenant_ids() returns setof text
language sql security definer stable as $$
  select tenant_id from memberships where user_id = auth.uid()
$$;

-- Example policy (repeat per table): only rows for the user's tenants.
create policy tenant_isolation on products
  using (tenant_id in (select my_tenant_ids()))
  with check (tenant_id in (select my_tenant_ids()));
-- ...same for variations, suppliers, sales, sale_items, staff, and
--    (on tenants) id in (select my_tenant_ids()).
```

Then:

- Enable **Supabase Auth** (email/password or magic link). Each shop owner signs
  up; you insert a `memberships` row linking them to their `tenant_id`.
- Redeploy the Edge Function **without** `--no-verify-jwt` and have the client
  send the user's Supabase access token; drop the service-role key from the pull
  path so RLS is enforced. (The in-shop staff PIN stays as the till-level login on
  top of the account.)
- Make stock decrements a Postgres RPC (a single `update ... set stock = stock -
  qty`) so concurrent registers can't oversell.
- Move product/logo images to **Supabase Storage** instead of base64.

At that point you have a multi-tenant SaaS: many customers, one database, each
isolated by RLS, scalable on Supabase's Postgres and Netlify's CDN.

---

## Rollback / safety

- The local `.sqlite` backup (Settings → Backup) is always a full snapshot; keep
  one before switching the API base.
- Clearing the API base returns any register to standalone offline mode.
- Supabase keeps automatic backups; the `service_role` key must live only in the
  Edge Function's secrets, never in the frontend.
