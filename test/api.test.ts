import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { createApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { BETH, MORTY, RICK, SUMMER } from '../src/mock/fixtures.js';
import { MockGraphClient } from '../src/mock/mockGraph.js';

const principal = (roles: string[], name = 'Ops Person') =>
  Buffer.from(
    JSON.stringify({
      auth_typ: 'aad',
      name_typ: 'name',
      role_typ: 'roles',
      claims: [{ typ: 'name', val: name }, ...roles.map((r) => ({ typ: 'roles', val: r }))],
    }),
  ).toString('base64');

const operator = principal(['MSUser.Operator']);

function app() {
  const graph = new MockGraphClient();
  const config = loadConfig({ NODE_ENV: 'test', MOCK_GRAPH: 'true' });
  return { app: createApp(config, { graph }), graph };
}

describe('auth', () => {
  it('serves /healthz without authentication', async () => {
    await request(app().app).get('/healthz').expect(200, { status: 'ok' });
  });

  it('rejects API calls without an Easy Auth principal', async () => {
    await request(app().app).get('/api/me').expect(401);
  });

  it('rejects signed-in users without the operator role', async () => {
    await request(app().app).get('/api/me').set('x-ms-client-principal', principal(['Other'])).expect(403);
  });

  it('rejects a malformed principal header', async () => {
    await request(app().app).get('/api/me').set('x-ms-client-principal', 'not-base64-json').expect(401);
  });

  it('returns the operator name', async () => {
    const res = await request(app().app).get('/api/me').set('x-ms-client-principal', operator).expect(200);
    expect(res.body).toMatchObject({ name: 'Ops Person', mock: true });
  });

  it('refuses AUTH_DISABLED in production', () => {
    expect(() => loadConfig({ NODE_ENV: 'production', AUTH_DISABLED: 'true' })).toThrow();
  });
});

describe('API', () => {
  const get = (path: string) => request(app().app).get(path).set('x-ms-client-principal', operator);

  it('returns the Secure Score', async () => {
    const res = await get('/api/securescore').expect(200);
    expect(res.body.data).toMatchObject({ percentage: 63, stars: 3, allTenantsAveragePercentage: 46 });
  });

  it('returns the five most recent active risks, newest first', async () => {
    const res = await get('/api/risk/recent').expect(200);
    expect(res.body.data).toHaveLength(5);
    expect(res.body.data[0].id).toBe('rd-01');
    expect(res.body.data.every((r: { state: string }) => r.state === 'atRisk')).toBe(true);
  });

  it('searches users and classifies account types', async () => {
    const res = await get('/api/users?q=smith').expect(200);
    const types = Object.fromEntries(res.body.data.map((u: { id: string; accountType: string }) => [u.id, u.accountType]));
    expect(types).toEqual({ [MORTY]: 'Cloud', [SUMMER]: 'B2B', [BETH]: 'Hybrid' });
  });

  it('validates search input', async () => {
    await get('/api/users?q=a').expect(400);
    await get('/api/users?q=%3Cscript%3E').expect(400);
    await get('/api/users').expect(400);
  });

  it('builds a full profile in one Graph batch', async () => {
    const { app: a, graph } = app();
    const res = await request(a).get(`/api/users/${RICK}/profile`).set('x-ms-client-principal', operator).expect(200);
    expect(res.body.user.accountType).toBe('Hybrid');
    expect(res.body.user.manager).toBe('Beth Smith');
    expect(res.body.assessment.overall.level).toBe('danger');
    expect(res.body.hibp.data.breaches).toHaveLength(2);
    expect(res.body.signIns.data).toHaveLength(4);
    expect(graph.calls).toHaveLength(7);
  });

  it('rates a well-configured user as great', async () => {
    const res = await get(`/api/users/${MORTY}/profile`).expect(200);
    expect(res.body.assessment.overall).toMatchObject({ level: 'good', score: 0 });
    expect(res.body.assessment.devices.level).toBe('good');
  });

  it('rejects non-GUID ids and 404s unknown users', async () => {
    await get('/api/users/rick@contoso.example/profile').expect(400);
    await get('/api/users/00000000-0000-0000-0000-000000000000/profile').expect(404);
  });

  it('sets security headers and no-store on the API', async () => {
    const res = await get('/api/securescore');
    expect(res.headers['cache-control']).toBe('no-store');
    const page = await request(app().app).get('/').expect(200);
    expect(page.headers['content-security-policy']).toContain("script-src 'self'");
    expect(page.headers['x-powered-by']).toBeUndefined();
  });
});
