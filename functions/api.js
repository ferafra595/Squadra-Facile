// Endpoint: GET /api — verifica la connessione al database D1.
export async function onRequestGet({ env }) {
  if (!env.DB) return Response.json({ status: 'error', database: 'binding_missing' }, { status: 503 });
  try {
    const result = await env.DB.prepare('SELECT 1 AS ok').first();
    return Response.json({ status: 'ok', database: result?.ok === 1 ? 'connected' : 'error' });
  } catch {
    return Response.json({ status: 'error', database: 'not_connected' }, { status: 503 });
  }
}
