import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { createApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import type { GraphRequest, GraphVersion } from '../src/graph/client.js';
import { BETH, BREAKGLASS, MORTY, RICK, SUMMER } from '../src/mock/fixtures.js';
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

  it('builds a full profile from one v1.0 batch, one beta batch and cached tenant policies', async () => {
    const { app: a, graph } = app();
    const res = await request(a).get(`/api/users/${RICK}/profile`).set('x-ms-client-principal', operator).expect(200);
    expect(res.body.user.accountType).toBe('Hybrid');
    expect(res.body.user.manager).toBe('Beth Smith');
    expect(res.body.assessment.overall.level).toBe('danger');
    expect(res.body.hibp.data.breaches).toHaveLength(2);
    expect(res.body.signIns.data).toHaveLength(4);
    expect(res.body.signIns.data[0].authMethods).toEqual(['Password', 'Text message']);
    expect(graph.calls).toHaveLength(17 + 1 + 2);
    expect(graph.calls.filter((c) => c.startsWith('/beta/'))).toEqual([expect.stringMatching(/^\/beta\/auditLogs\/signIns\?/)]);

    // tenant policies are read once, not per profile
    await request(a).get(`/api/users/${MORTY}/profile`).set('x-ms-client-principal', operator).expect(200);
    expect(graph.calls.filter((c) => c.startsWith('/policies/'))).toHaveLength(2);
  });

  it('explains a risky privileged account', async () => {
    const { body } = await get(`/api/users/${RICK}/profile`).expect(200);
    expect(body.identity).toMatchObject({ isPrivileged: true, isBreakGlass: false, licensedWorkloads: ['Mailbox', 'Teams', 'SharePoint / OneDrive'] });
    expect(body.assessment.overall.reasons).toContain('1 permanently active high-impact role');
    expect(body.authStrength.data.verdict).toBe('phishable');
    expect(body.privilege.data.assignments.map((a: { roleName: string; state: string }) => `${a.roleName}:${a.state}`)).toEqual([
      'Global Administrator:permanentActive',
      'Exchange Administrator:timeBoundActive',
      'Security Administrator:eligible',
      'Message Center Reader:permanentActive',
    ]);
    expect(body.assessment.pimDrift.level).toBe('warning');
    expect(body.assessment.ownership).toMatchObject({ level: 'danger', label: 'Owns 1 role-assignable group' });
    expect(body.ownership.data.counts).toMatchObject({ application: 1, servicePrincipal: 1, agent: 1 });
    expect(body.assessment.credentialChanges.level).toBe('danger');
    const adminChange = body.credentialChanges.data.events.find((e: { activity: string }) => e.activity === 'Admin registered security info');
    expect(adminChange.flags).toEqual(['Made by helpdesk.temp@contoso.example', 'Within 72 hours of Suspicious credential addition']);
    expect(body.assessment.adminHygiene.level).toBe('danger');
    expect(body.assessment.caPosture.level).toBe('warning');
  });

  it('rates a well-configured user as great', async () => {
    const res = await get(`/api/users/${MORTY}/profile`).expect(200);
    expect(res.body.assessment.overall).toMatchObject({ level: 'good', score: 0, reasons: [] });
    expect(res.body.assessment.devices.level).toBe('good');
    expect(res.body.authStrength.data.verdict).toBe('phishingResistant');
    expect(res.body.tenant.notes).toEqual([]);
  });

  it('recognises break-glass and guest identities', async () => {
    const bg = await get(`/api/users/${BREAKGLASS}/profile`).expect(200);
    expect(bg.body.identity.isBreakGlass).toBe(true);
    expect(bg.body.assessment.privilege.level).toBe('info');
    expect(bg.body.assessment.pimDrift.level).toBe('info');
    expect(bg.body.assessment.overall.level).toBe('good');

    const guest = await get(`/api/users/${SUMMER}/profile`).expect(200);
    expect(guest.body.assessment.authStrength.level).toBe('info');
  });

  it('flags guest footprint and membership sprawl', async () => {
    const { body } = await get(`/api/users/${BETH}/profile`).expect(200);
    expect(body.guests.data.footprint).toBe(34);
    expect(body.assessment.guests.level).toBe('danger');
    expect(body.membership.data).toMatchObject({ directGroups: 90, transitiveGroups: 260 });
    expect(body.membership.data.sensitiveGroups.map((g: { displayName: string }) => g.displayName)).toEqual(['Finance - Payroll']);
    expect(body.assessment.membership.level).toBe('warning');
    expect(body.assessment.recovery).toMatchObject({ level: 'warning', label: 'A Temporary Access Pass is active' });
    expect(body.assessment.pimDrift.level).toBe('good');
  });

  it('keeps the profile when new sections are forbidden, unlicensed or beta fails', async () => {
    class DegradedGraph extends MockGraphClient {
      override async batch(requests: GraphRequest[], opts: { version?: GraphVersion } = {}) {
        if (opts.version === 'beta') throw new Error('beta is down');
        const responses = await super.batch(requests, opts);
        responses.set('ownedObjects', { status: 403, body: { error: { code: 'Authorization_RequestDenied', message: 'Insufficient privileges' } } });
        const p2 = { status: 403, body: { error: { code: 'AadPremiumLicenseRequired', message: 'The tenant needs an AAD Premium 2 license.' } } };
        if (responses.has('roleSchedules')) {
          responses.set('roleSchedules', p2);
          responses.set('roleEligibilities', p2);
        }
        return responses;
      }
    }
    const config = loadConfig({ NODE_ENV: 'test', MOCK_GRAPH: 'true' });
    const res = await request(createApp(config, { graph: new DegradedGraph() }))
      .get(`/api/users/${RICK}/profile`)
      .set('x-ms-client-principal', operator)
      .expect(200);
    expect(res.body.ownership).toMatchObject({ status: 'unavailable', reason: 'forbidden' });
    expect(res.body.ownership.message).toMatch(/application permissions/);
    expect(res.body.assessment.ownership.level).toBe('unknown');
    // falls back to plain role assignments: everything is permanent, no PIM detail
    expect(res.body.privilege.data.pimDetail).toBe(false);
    expect(res.body.assessment.pimDrift.level).toBe('info');
    expect(res.body.authStrength.data.observed).toBeNull();
    expect(res.body.tenant.notes).toEqual(
      expect.arrayContaining([expect.stringMatching(/PIM schedules need/), expect.stringMatching(/Graph beta\) are unavailable/)]),
    );
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
