/*
 * Totals POS - Sync API as a Netlify Function
 * ---------------------------------------------------------------------------
 * Implements the SAME contract the app already speaks (/api/sync, /api/pull)
 * but backed by Supabase Postgres. Deploying this needs no Supabase CLI and no
 * Edge Function UI: it deploys automatically when Netlify is connected to this
 * repo. The only configuration is two Netlify environment variables:
 *
 *   SUPABASE_URL               e.g. https://xxxxxxxx.supabase.co
 *   SUPABASE_SERVICE_ROLE_KEY  Project Settings -> API -> service_role key
 *
 * The service-role key is read only here on the server; it is never sent to the
 * browser. Set both in Netlify: Site settings -> Environment variables.
 */
import { createClient } from '@supabase/supabase-js';

const url = process.env.SUPABASE_URL;
const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
const db = url && key ? createClient(url, key, { auth: { persistSession: false } }) : null;

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'content-type, authorization',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Content-Type': 'application/json'
};
const json = (statusCode, body) => ({ statusCode, headers: CORS, body: JSON.stringify(body) });

export async function handler(event) {
  if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers: CORS, body: '' };
  if (!db) return json(500, { error: 'Server not configured: set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in Netlify.' });

  const path = event.path || '';
  const route = path.endsWith('/sync') ? 'sync' : path.endsWith('/pull') ? 'pull' : '';

  try {
    // PUSH — registers upload their outbox.
    if (route === 'sync' && event.httpMethod === 'POST') {
      const { changes = [] } = JSON.parse(event.body || '{}');
      const applied = [];
      for (const ch of changes) {
        try {
          const p = ch.payload || {};
          if (ch.entity === 'tenant') {
            await db.from('tenants').upsert({ id: ch.entity_id, ...p });
          } else if (ch.entity === 'product') {
            if (p.product) await db.from('products').upsert(p.product);
            if (Array.isArray(p.variations)) for (const v of p.variations) await db.from('variations').upsert(v);
          } else if (ch.entity === 'staff') {
            await db.from('staff').upsert({ id: ch.entity_id, ...p });
          } else if (ch.entity === 'stock') {
            const { data } = await db.from('variations').select('stock').eq('id', ch.entity_id).single();
            const cur = Number((data && data.stock) || 0);
            const next = ch.op === 'set' ? Number(p.stock || 0) : cur - Number(p.qty || 0);
            await db.from('variations').update({ stock: next, updated_at: new Date().toISOString() }).eq('id', ch.entity_id);
          } else if (ch.entity === 'sale') {
            if (p.sale) await db.from('sales').upsert(p.sale);
            if (Array.isArray(p.items)) for (const it of p.items) {
              await db.from('sale_items').upsert({ id: cryptoId(), sale_id: ch.entity_id, ...it });
            }
          }
          applied.push(ch.id);
        } catch (e) { /* leave un-applied; the register retries next sync */ }
      }
      return json(200, { applied });
    }

    // PULL — registers download rows changed since their cursor.
    if (route === 'pull' && event.httpMethod === 'GET') {
      const since = Number((event.queryStringParameters && event.queryStringParameters.since) || 0);
      const pick = async (t) => (await db.from(t).select('*').gt('seq', since).order('seq')).data || [];
      const tenants = await pick('tenants');
      const products = await pick('products');
      const variations = await pick('variations');
      const staff = await pick('staff');
      const maxSeq = [...tenants, ...products, ...variations, ...staff]
        .reduce((m, r) => Math.max(m, r.seq || 0), since);
      return json(200, { cursor: maxSeq, tenants, products, variations, staff });
    }

    return json(404, { error: 'not found', path });
  } catch (e) {
    return json(500, { error: String((e && e.message) || e) });
  }
}

function cryptoId() {
  return 'si_' + (globalThis.crypto && crypto.randomUUID ? crypto.randomUUID() : Date.now().toString(36) + Math.random().toString(36).slice(2));
}
