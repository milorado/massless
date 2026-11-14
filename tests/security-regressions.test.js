import test from 'node:test';
import assert from 'node:assert/strict';
import { signApi } from '../src/sign.js';
import { sitesApi, serveSite, _resetSiteCaches } from '../src/sites.js';
import { FakeD1, FakeR2, fakeEnv } from '../tools/sign/fakes.mjs';

const request = (path, token, body, method = 'POST') => new Request('https://chucksi.com' + path, {
  method, headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
  body: body === undefined ? undefined : JSON.stringify(body),
});
const upload = (text) => {
  const form = new FormData();
  form.append('meta', JSON.stringify({ slug: 'cedar-house', paths: ['index.html'] }));
  form.append('f0', new Blob([`<html><head><meta name="generator" content="Chucksi Website"></head><body>${text}</body></html>`]));
  return form;
};

// Deterministic schedules exercise actual handlers/SQL while all provider calls stay mocked.
test('a rejected concurrent signature cannot overwrite the accepted payload', async () => {
  const env = await fakeEnv();
  const form = new FormData();
  form.append('meta', JSON.stringify({ docHash: 'a'.repeat(64), signers: [{}] }));
  form.append('blob', new Blob([new Uint8Array(100).fill(1)]));
  const created = await (await signApi(new Request('https://chucksi.com/api/sign/envelopes', { method: 'POST', body: form }), env)).json();
  const path = `/api/sign/envelopes/${created.id}/events`, token = created.signerTokens[0];
  const event = (body) => signApi(request(path, token, { docHash: 'a'.repeat(64), ...body }), env);
  assert.equal((await event({ type: 'consented' })).status, 200);
  let writes = 0, firstReached, secondReached, releaseSecond;
  const firstBarrier = new Promise((r) => { firstReached = r; });
  const secondBarrier = new Promise((r) => { secondReached = r; });
  const secondWait = new Promise((r) => { releaseSecond = r; });
  const put = env.SIGN_BUCKET.put.bind(env.SIGN_BUCKET);
  env.SIGN_BUCKET.put = async (key, bytes, opts) => {
    if (/\/s0(?:\/|$)/.test(key)) {
      if (++writes === 1) { firstReached(); await secondBarrier; }
      else { secondReached(); await secondWait; }
    }
    return put(key, bytes, opts);
  };
  const payload = (marker) => Buffer.from(new Uint8Array(30).fill(marker).map((v, i) => i ? v : 1)).toString('base64url');
  const first = event({ type: 'signed', payload: payload(11), valuesHash: 'b'.repeat(64) });
  await firstBarrier;
  const second = event({ type: 'signed', payload: payload(22), valuesHash: 'c'.repeat(64) });
  const accepted = await first;
  releaseSecond();
  assert.equal(accepted.status, 200);
  assert.equal((await second).status, 409);
  const result = await (await signApi(request(`/api/sign/envelopes/${created.id}`, token, undefined, 'GET'), env)).json();
  assert.equal(result.payloads[0].data, payload(11));
  const rows = env.SIGN_DB.dump();
  assert.equal(JSON.parse(rows.sign_events.find((e) => e.type === 'signed').detail).valuesHash, 'b'.repeat(64));
  assert.equal(rows.sign_envelopes[0].bytes, 130);
  assert.equal([...env.SIGN_BUCKET.objects.keys()].filter((k) => /\/s0(?:\/|$)/.test(k)).length, 1);
});

test('concurrent publishing preserves the complete winning release', async (t) => {
  const oldFetch = globalThis.fetch;
  t.after(() => { globalThis.fetch = oldFetch; _resetSiteCaches(); });
  globalThis.fetch = async (url) => {
    assert.equal(url, 'https://auth.invalid/auth/v1/user');
    return Response.json({ id: 'owner', email_confirmed_at: '2026-01-01' });
  };
  const env = { SITES_DB: new FakeD1(new URL('../migrations/sites/0001_init.sql', import.meta.url).pathname), SITES_BUCKET: new FakeR2(), SUPABASE_URL: 'https://auth.invalid', SUPABASE_PUBLISHABLE_KEY: 'fake' };
  const publish = (text, method) => sitesApi(new Request('https://chucksi.com/api/sites' + (method === 'PUT' ? '/cedar-house' : ''), {
    method, headers: { authorization: 'Bearer fake' }, body: upload(text),
  }), env);
  assert.equal((await publish('initial', 'POST')).status, 201);
  let arrived = 0, release;
  const barrier = new Promise((r) => { release = r; });
  const put = env.SITES_BUCKET.put.bind(env.SITES_BUCKET);
  env.SITES_BUCKET.put = async (key, bytes, opts) => {
    if (key.endsWith('/index.html')) { if (++arrived === 2) release(); await barrier; }
    return put(key, bytes, opts);
  };
  const results = await Promise.all([publish('winner-A', 'PUT'), publish('winner-B', 'PUT')]);
  assert.deepEqual(results.map((r) => r.status).sort(), [200, 409]);
  _resetSiteCaches();
  const visit = await serveSite(new Request('https://cedar-house.v2web.site/'), env, {}, { kind: 'site', slug: 'cedar-house' });
  assert.equal(visit.status, 200);
  assert.match(await visit.text(), results[0].status === 200 ? /winner-A/ : /winner-B/);
});

test('existing signatures and site releases remain readable after additive migrations', async (t) => {
  const env = await fakeEnv();
  const docHash = 'a'.repeat(64), form = new FormData();
  form.append('meta', JSON.stringify({ docHash, signers: [{}] }));
  form.append('blob', new Blob([new Uint8Array(100).fill(1)]));
  const created = await (await signApi(new Request('https://chucksi.com/api/sign/envelopes', { method: 'POST', body: form }), env)).json();
  const payload = Buffer.from(new Uint8Array(30).fill(1)).toString('base64url');
  await env.SIGN_BUCKET.put(`e/${created.id}/s0`, Buffer.from(payload, 'base64url'));
  await env.SIGN_DB.prepare("UPDATE sign_signers SET status = 'signed', payload_bytes = 30 WHERE envelope_id = ?").bind(created.id).run();
  const signed = await (await signApi(request(`/api/sign/envelopes/${created.id}`, created.ownerToken, undefined, 'GET'), env)).json();
  assert.equal(signed.payloads[0].data, payload);

  const oldFetch = globalThis.fetch;
  t.after(() => { globalThis.fetch = oldFetch; _resetSiteCaches(); });
  globalThis.fetch = async () => Response.json({ id: 'owner', email_confirmed_at: '2026-01-01' });
  const sites = { SITES_DB: new FakeD1(new URL('../migrations/sites/0001_init.sql', import.meta.url).pathname), SITES_BUCKET: new FakeR2(), SUPABASE_URL: 'https://auth.invalid', SUPABASE_PUBLISHABLE_KEY: 'fake' };
  await sites.SITES_DB.prepare('INSERT INTO sites (slug, owner, created_at, updated_at) VALUES (?, ?, ?, ?)').bind('cedar-house', 'owner', 1, 1).run();
  await sites.SITES_BUCKET.put('sites/cedar-house/v1/index.html', '<html><body>Legacy</body></html>');
  await sites.SITES_BUCKET.put('sites/cedar-house/manifest.json', JSON.stringify({ slug: 'cedar-house', version: 1, files: { 'index.html': { etag: 'legacy' } } }));
  const visit = () => serveSite(new Request('https://cedar-house.v2web.site/'), sites, {}, { kind: 'site', slug: 'cedar-house' });
  assert.match(await (await visit()).text(), /Legacy/);
  assert.equal((await sitesApi(new Request('https://chucksi.com/api/sites/cedar-house', { method: 'PUT', headers: { authorization: 'Bearer fake' }, body: upload('Migrated') }), sites)).status, 200);
  assert.match(await (await visit()).text(), /Migrated/);
});

test('a failed staged upload preserves the previous published release', async (t) => {
  const oldFetch = globalThis.fetch;
  t.after(() => { globalThis.fetch = oldFetch; _resetSiteCaches(); });
  globalThis.fetch = async () => Response.json({ id: 'owner', email_confirmed_at: '2026-01-01' });
  const env = { SITES_DB: new FakeD1(new URL('../migrations/sites/0001_init.sql', import.meta.url).pathname), SITES_BUCKET: new FakeR2(), SUPABASE_URL: 'https://auth.invalid', SUPABASE_PUBLISHABLE_KEY: 'fake' };
  const publish = (text, method) => sitesApi(new Request('https://chucksi.com/api/sites' + (method === 'PUT' ? '/cedar-house' : ''), { method, headers: { authorization: 'Bearer fake' }, body: upload(text) }), env);
  assert.equal((await publish('Keep this', 'POST')).status, 201);
  const original = await env.SITES_DB.prepare('SELECT manifest_json FROM sites').first('manifest_json');
  const keys = [...env.SITES_BUCKET.objects.keys()];
  const put = env.SITES_BUCKET.put.bind(env.SITES_BUCKET);
  env.SITES_BUCKET.put = async (...args) => { await put(...args); throw new Error('storage unavailable'); };
  assert.equal((await publish('Failed replacement', 'PUT')).status, 500);
  assert.equal(await env.SITES_DB.prepare('SELECT manifest_json FROM sites').first('manifest_json'), original);
  assert.deepEqual([...env.SITES_BUCKET.objects.keys()], keys);
  const response = await serveSite(new Request('https://cedar-house.v2web.site/'), env, {}, { kind: 'site', slug: 'cedar-house' });
  assert.equal(response.status, 200);
  assert.match(await response.text(), /Keep this/);
});
