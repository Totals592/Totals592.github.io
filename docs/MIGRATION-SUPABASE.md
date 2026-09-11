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
  foreach t in array array['tenants','products','variations','staff','sales','sale_items']
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
          // Use the client's item id (falls back to a uuid) so replays don't duplicate lines.
          if (p.items) for (const it of p.items)
            await db.from("sale_items").upsert({ id: it.id || crypto.randomUUID(), sale_id: ch.entity_id, ...it });
        }
        applied.push(ch.id);
      } catch (_) { /* leave un-applied; the register retries */ }
    }
    return json({ applied });
  }

  // PULL: registers download rows changed since their per-table cursor.
  if (url.pathname.endsWith("/pull") && req.method === "GET") {
    const qp = url.searchParams;
    const legacy = Number(qp.get("since") || 0);
    const cur = (name: string) => Number(qp.get(name + "_since") ?? legacy) || 0;
    const pick = async (t: string) =>
      (await db.from(t).select("*").gt("seq", cur(t)).order("seq")).data || [];
    const tenants = await pick("tenants");
    const products = await pick("products");
    const variations = await pick("variations");
    const staff = await pick("staff");
    const sales = await pick("sales");           // sales now replicate to every device
    const sale_items = await pick("sale_items");
    return json({ tenants, products, variations, staff, sales, sale_items });
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
isolated by RLS, scalable on Supabase's Postgres and served from GitHub Pages'
CDN.

---

## Rollback / safety

- The local `.sqlite` backup (Settings → Backup) is always a full snapshot; keep
  one before switching the API base.
- Clearing the API base returns any register to standalone offline mode.
- Supabase keeps automatic backups; the `service_role` key must live only in the
  Edge Function's secrets, never in the frontend.
