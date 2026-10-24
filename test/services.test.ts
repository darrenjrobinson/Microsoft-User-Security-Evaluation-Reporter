import { describe, expect, it } from 'vitest';
import type { GraphBinary, GraphClient, GraphRequest, GraphResponse } from '../src/graph/client.js';
import { allPages, continuationOf } from '../src/graph/paging.js';
import { parsePolicy } from '../src/policy.js';
import { buildAuthStrength, observeSignIns } from '../src/services/authStrength.js';
import { buildCredentialChanges } from '../src/services/credentialChanges.js';
import { buildPrivilege } from '../src/services/privilege.js';
import { createSkuCatalog, licencesOf, toLicence } from '../src/services/licences.js';
import { createPhotoService } from '../src/services/photo.js';
import { buildGuests } from '../src/services/relationships.js';
import { createTenantContext } from '../src/services/tenantContext.js';
import type { RiskDetectionView } from '../src/services/risk.js';
import { ok } from '../src/services/section.js';

const USER = '6e7b768e-07e2-4810-8459-485f84f8f204';
const GA = '62e90394-69f5-4237-9190-012177145e10';
const policy = parsePolicy();

const list = (value: unknown[], extra: Record<string, unknown> = {}): GraphResponse => ({ status: 200, body: { value, ...extra } });
const fail = (status: number, code = 'Forbidden', message = 'Insufficient privileges'): GraphResponse => ({ status, body: { error: { code, message } } });
const role = (over: Record<string, unknown> = {}) => ({
  principalId: USER,
  roleDefinitionId: GA,
  directoryScopeId: '/',
  endDateTime: null,
  assignmentType: 'Assigned',
  memberType: 'Direct',
  roleDefinition: { displayName: 'Global Administrator', templateId: GA },
  ...over,
});

describe('privilege', () => {
  it('flags time-bound direct assignments of required-PIM roles, not activations or eligibility', () => {
    const p = buildPrivilege(
      {
        schedules: list([role({ endDateTime: '2099-01-01T00:00:00Z' }), role({ assignmentType: 'Activated', endDateTime: '2099-01-01T00:00:00Z' })]),
        eligibilities: list([role()]),
      },
      USER,
      policy,
    );
    expect(p.status === 'ok' && p.data.assignments.map((a) => [a.state, a.pimDrift])).toEqual([
      ['timeBoundActive', true],
      ['activated', false],
      ['eligible', false],
    ]);
  });

  it('includes roles held through role-assignable groups, including without P2', () => {
    const noP2 = fail(403, 'AadPremiumLicenseRequired', 'The tenant needs an AAD Premium 2 license.');
    const p = buildPrivilege({ schedules: noP2, assignments: list([]), eligibilities: noP2 }, USER, policy, {
      results: [{ groupName: 'Tier 0 Admins', schedules: noP2, assignments: list([role({ principalId: 'group' })]), eligibilities: noP2 }],
      gaps: [],
    });
    expect(p.status === 'ok' && p.data).toMatchObject({
      pimDetail: false,
      gaps: [],
      assignments: [{ roleName: 'Global Administrator', via: 'group', groupName: 'Tier 0 Admins', state: 'permanentActive', impact: 'high' }],
    });
  });

  it('records a failed eligibility lookup instead of treating it as no eligible roles', () => {
    const p = buildPrivilege({ schedules: list([]), eligibilities: fail(429, 'TooManyRequests', 'Throttled') }, USER, policy);
    expect(p.status === 'ok' && p.data.gaps).toEqual(["Eligible (PIM) roles for this user couldn't be read: Throttled"]);
  });
});

describe('guest governance', () => {
  it('counts only successful invitations and marks a refused sponsorship lookup as a gap', () => {
    const invite = (id: string, result: string) => ({ activityDateTime: '2026-10-20T00:00:00Z', result, targetResources: [{ id }] });
    const g = buildGuests(
      { res: fail(403), complete: true },
      { res: list([invite('a', 'success'), invite('b', 'failure'), invite('c', 'success')]), complete: true },
    );
    expect(g.status === 'ok' && g.data).toMatchObject({ sponsored: null, footprint: 2, complete: false });
    expect(g.status === 'ok' && g.data.gaps[0]).toMatch(/application permissions/);
  });
});

describe('credential changes', () => {
  const detection = (over: Partial<RiskDetectionView>) =>
    ({ type: 'unfamiliarFeatures', typeLabel: 'Unfamiliar sign-in properties', state: 'atRisk', detectedDateTime: '', activityDateTime: null, ...over }) as RiskDetectionView;
  const audit = (activityDateTime: string, result = 'success') => ({
    activityDateTime,
    activityDisplayName: 'User registered security info',
    result,
    initiatedBy: { user: { id: USER, userPrincipalName: 'u@x' } },
  });
  const now = new Date('2026-10-24T00:00:00Z');

  it('ignores failed operations and correlates on when the risky activity happened', () => {
    // detected five days after the activity, which was one day before the registration
    const late = detection({ activityDateTime: '2026-10-19T00:00:00Z', detectedDateTime: '2026-10-25T00:00:00Z' });
    const c = buildCredentialChanges(ok([audit('2026-10-20T00:00:00Z'), audit('2026-10-21T00:00:00Z', 'failure')]), ok([]), ok([late]), [], USER, now);
    expect(c.status === 'ok' && c.data.events.map((e) => e.flags)).toEqual([['Within 72 hours of Unfamiliar sign-in properties']]);
  });

  it('only treats active suspicious credential additions as a signal', () => {
    const resolved = detection({ type: 'suspiciousCredentialAddition', state: 'remediated', detectedDateTime: '2026-10-20T00:00:00Z' });
    const c = buildCredentialChanges(ok([]), ok([]), ok([resolved]), [], USER, now);
    expect(c.status === 'ok' && c.data.suspiciousDetections).toEqual([]);
  });
});

describe('authentication strength', () => {
  it('stays unavailable when the only evidence is an empty sign-in set', () => {
    const unavailable = { status: 'unavailable', reason: 'forbidden', message: 'no access' } as const;
    expect(buildAuthStrength(unavailable, unavailable, ok(observeSignIns([]))).status).toBe('unavailable');
  });
});

describe('paging', () => {
  const request: GraphRequest = { id: 'memberOf', method: 'GET', url: `/users/${USER}/memberOf?$top=999` };
  const next = (token: string) => `https://graph.microsoft.com/v1.0/users/${USER}/memberOf?$top=999&$skiptoken=${token}`;
  const fakeGraph = (pages: Record<string, GraphResponse>): GraphClient & { calls: string[] } => ({
    calls: [],
    async get<T>(url: string) {
      this.calls.push(url);
      const page = pages[url];
      if (!page) throw new Error(`unexpected ${url}`);
      return page as GraphResponse<T>;
    },
    async batch() {
      return new Map();
    },
    async getBinary() {
      return { status: 404, contentType: '', body: Buffer.alloc(0) };
    },
  });

  it('follows continuation links back to the same path', async () => {
    const graph = fakeGraph({
      [`/users/${USER}/memberOf?$top=999&$skiptoken=p2`]: list([3], { '@odata.nextLink': next('p3') }),
      [`/users/${USER}/memberOf?$top=999&$skiptoken=p3`]: list([4]),
    });
    const paged = await allPages(graph, request, list([1, 2], { '@odata.nextLink': next('p2') }));
    expect(paged.complete).toBe(true);
    expect((paged.res!.body as { value: number[] }).value).toEqual([1, 2, 3, 4]);
  });

  it('refuses continuation links to other hosts or paths and reports the result as incomplete', async () => {
    expect(continuationOf('https://evil.example/v1.0/users', request)).toBeNull();
    expect(continuationOf(`https://graph.microsoft.com/v1.0/users/${USER}/ownedObjects`, request)).toBeNull();
    expect(continuationOf(`https://graph.microsoft.com/beta/users/${USER}/memberOf`, request)).toBeNull();
    const graph = fakeGraph({});
    const paged = await allPages(graph, request, list([1], { '@odata.nextLink': 'https://evil.example/steal' }));
    expect(paged.complete).toBe(false);
    expect(graph.calls).toEqual([]);
  });

  it('stops at a failed page and keeps what it has', async () => {
    const paged = await allPages(fakeGraph({}), request, list([1], { '@odata.nextLink': next('p2') }));
    expect(paged).toMatchObject({ complete: false, res: { body: { value: [1] } } });
  });
});

describe('photos', () => {
  const graphWith = (responses: GraphBinary[]): GraphClient & { urls: string[] } => ({
    urls: [],
    async get() {
      throw new Error('unused');
    },
    async batch() {
      return new Map();
    },
    async getBinary(url: string) {
      this.urls.push(url);
      return responses.shift() ?? { status: 404, contentType: '', body: Buffer.alloc(0) };
    },
  });
  const png = { status: 200, contentType: 'image/png', body: Buffer.from('89504e47', 'hex') };

  it('falls back to the default photo when the fixed size is missing', async () => {
    const graph = graphWith([{ status: 404, contentType: '', body: Buffer.alloc(0) }, png]);
    expect(await createPhotoService(graph)(USER)).toEqual({ contentType: 'image/png', body: png.body });
    expect(graph.urls).toHaveLength(2);
  });

  it('refuses non-raster or oversized images and stops on errors other than 404', async () => {
    expect(await createPhotoService(graphWith([{ ...png, contentType: 'image/svg+xml' }]))(USER)).toBeNull();
    expect(await createPhotoService(graphWith([{ ...png, body: Buffer.alloc(1_000_001) }]))(USER)).toBeNull();
    const forbidden = graphWith([{ status: 403, contentType: 'application/json', body: Buffer.alloc(0) }, png]);
    expect(await createPhotoService(forbidden)(USER)).toBeNull();
    expect(forbidden.urls).toHaveLength(1);
  });
});

describe('licences', () => {
  it('names common SKUs, flags frontline ones and passes unknown ones through', () => {
    expect(toLicence('id-1', 'SPE_E5')).toEqual({ skuId: 'id-1', skuPartNumber: 'SPE_E5', name: 'Microsoft 365 E5', frontline: false });
    expect(toLicence('id-2', 'M365_F1_COMM').frontline).toBe(true);
    expect(toLicence('id-3', 'DESKLESSPACK')).toMatchObject({ name: 'Office 365 F3', frontline: true });
    expect(toLicence('id-4', 'CONTOSO_CUSTOM')).toMatchObject({ name: 'CONTOSO_CUSTOM', frontline: false });
  });

  it('resolves assignedLicenses through the SKU catalog and falls back to ids without it', () => {
    const user = { assignedLicenses: [{ skuId: 'AAA' }, { skuId: 'bbb' }] };
    const catalog = new Map([['aaa', 'SPE_E3']]);
    expect(licencesOf(user, catalog).map((l) => l.name)).toEqual(['Microsoft 365 E3', 'Unrecognised licence (bbb)']);
    expect(licencesOf(user, null).every((l) => l.name.startsWith('Unrecognised licence'))).toBe(true);
    expect(licencesOf({}, catalog)).toEqual([]);
  });

  it('caches the SKU catalog and returns null when it cannot be read', async () => {
    let calls = 0;
    const graph = {
      async get() {
        calls++;
        return { status: 200, body: { value: [{ skuId: 'AAA', skuPartNumber: 'SPE_E3' }] } };
      },
    } as unknown as GraphClient;
    const getCatalog = createSkuCatalog(graph);
    expect((await getCatalog())?.get('aaa')).toBe('SPE_E3');
    await getCatalog();
    expect(calls).toBe(1);
    const failing = { async get() { throw new Error('403'); } } as unknown as GraphClient;
    expect(await createSkuCatalog(failing)()).toBeNull();
  });
});

describe('tenant context', () => {
  const graphReturning = (bodies: Record<string, unknown>) => {
    let calls = 0;
    const graph = {
      async batch() {
        calls++;
        return new Map(Object.entries(bodies).map(([id, body]) => [id, { status: 200, body }]));
      },
    } as unknown as GraphClient;
    return { graph, calls: () => calls };
  };

  it('keeps security defaults unknown when isEnabled is missing, instead of reporting it off', async () => {
    const { graph } = graphReturning({ authMethodsPolicy: { authenticationMethodConfigurations: [{ id: 'Fido2', state: 'enabled' }] }, securityDefaults: {} });
    const ctx = await createTenantContext(graph)();
    expect(ctx.status === 'ok' && ctx.data).toEqual({ methodsEnabled: ['Passkeys (FIDO2)'], methodsDisabled: [], securityDefaults: null });
  });

  it('reports empty policy responses as unavailable and does not cache them', async () => {
    const { graph, calls } = graphReturning({ authMethodsPolicy: {}, securityDefaults: {} });
    const getContext = createTenantContext(graph);
    expect((await getContext()).status).toBe('unavailable');
    await getContext();
    expect(calls()).toBe(2);
  });
});
