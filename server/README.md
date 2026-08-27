# Totals POS — Reference Cloud Backend

A **zero-dependency** Node.js server that the Totals POS Progressive Web App
syncs against. It is optional: the app is fully usable offline with no backend
at all. Deploy this when you want:

- Real-time sales & stock figures consolidated across every register/channel.
- To push updates (new items, price changes, tenant renames/suspensions) to
  shops **over the web, without visiting them**.
- Centralised, web-based tenant administration.
- Low-stock alerts to drive reordering.

## Run locally

```bash
cd server
ADMIN_TOKEN="pick-a-strong-secret" node server.js
# → http://localhost:4000        (health/status JSON)
# → http://localhost:4000/admin  (web control portal)
```

There is nothing to `npm install` — it uses only Node's standard library.
Data is persisted to `server/data.json` (swap for Postgres/Mongo in production
by replacing the storage helpers at the top of `server.js`).

## Connect the app

1. Deploy this server somewhere with HTTPS (Render, Railway, Fly.io, a VPS…).
2. In the PWA open **Settings → Cloud sync**, set **Cloud API base URL** to your
   server's origin (e.g. `https://your-backend.example.com`), and Save.
3. The register immediately begins pushing its outbox and pulling remote edits.
   Everything queued while offline uploads automatically once online.

## REST API

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/sync` | Registers push their outbox (sales, stock deltas, product/tenant edits). Returns applied change-ids. |
| `GET`  | `/api/pull?since=<cursor>` | Cursor-based download of tenants/products/variations changed since the register last synced. |
| `GET`  | `/api/alerts?tenant_id=` | Open low-stock alerts for reordering. |
| `GET`  | `/api/tenants` | Public tenant list. |
| `GET`  | `/health` | Service status + counts. |

### Admin API (send `Authorization: Bearer <ADMIN_TOKEN>`)

| Method | Path | Purpose |
|--------|------|---------|
| `GET`  | `/api/admin/tenants` | List all tenants. |
| `POST` | `/api/admin/tenants` | Create a tenant. |
| `PUT`  | `/api/admin/tenants/:id` | Rename / update / suspend a tenant. |
| `DELETE` | `/api/admin/tenants/:id` | Suspend a tenant. |

Admin edits are handed a new sequence number, so every register picks them up on
its next `/api/pull` — that is how a shop is updated remotely.

## Environment variables

| Var | Default | Notes |
|-----|---------|-------|
| `PORT` | `4000` | Listen port. |
| `ADMIN_TOKEN` | `change-me-admin-token` | **Set this before deploying.** |
| `DATA_FILE` | `./data.json` | Where the JSON store is written. |

## Production notes

- Put this behind HTTPS and restrict CORS (currently `*` for easy first-run).
- Replace the JSON file store with a real database for concurrency at scale.
- The `checkLowStock()` hook in `server.js` is where you would fan out
  email/SMS/webhook reorder notifications.
