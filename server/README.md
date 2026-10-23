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
ADMIN_KEY="pick-a-strong-secret" LICENSE_PRIVATE_KEY_PKCS8_B64="..." node server.js
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

Sync calls must identify the device: `X-Admin-Key: <ADMIN_KEY>` (the owner —
every shop) or `X-Device-Token: <token>` (one shop, from `/api/login`). Pulls are
filtered to the token's shop and pushes touching any other shop are refused.

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/login` | Public. Shop name + username + PIN → per-shop device token (8 wrong PINs lock for 15 min). |
| `POST` | `/api/signup` | Public. Sign-up request for a new shop (e-mails the owner if Resend is configured). |
| `GET`  | `/api/signups` · `POST /api/signups/approve` · `POST /api/signups/reject` | Admin key only. Review sign-ups; approving creates the shop, its manager and a 3-day trial. |
| `POST` | `/api/sync` | Registers push their outbox. Returns applied and rejected change-ids. |
| `GET`  | `/api/pull?<table>_since=<cursor>` | Per-table cursor download, scoped to the device's shop. |
| `GET`  | `/api/license?tenant_id=` | Signed subscription token for the device's shop. |
| `GET`  | `/api/whoami` | Which scope these credentials have. |
| `GET`  | `/api/alerts?tenant_id=` | Admin only. Open low-stock alerts. |
| `GET`  | `/health` | Service status + counts. |

### Admin API (send `Authorization: Bearer <ADMIN_KEY>` or `X-Admin-Key`)

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
| `ADMIN_KEY` | `change-me-admin-token` | **Set this before deploying.** (`ADMIN_TOKEN` still accepted.) |
| `LICENSE_PRIVATE_KEY_PKCS8_B64` | — | Signs licenses; also derives the device-token key. |
| `RESEND_API_KEY`, `NOTIFY_EMAIL`, `NOTIFY_FROM` | — | Optional sign-up e-mail notification. |
| `DATA_FILE` | `./data.json` | Where the JSON store is written. |

## Production notes

- Put this behind HTTPS and restrict CORS (currently `*` for easy first-run).
- Replace the JSON file store with a real database for concurrency at scale.
- The `checkLowStock()` hook in `server.js` is where you would fan out
  email/SMS/webhook reorder notifications.
