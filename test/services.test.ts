import { describe, expect, it } from 'vitest';
import type { GraphClient, GraphRequest, GraphResponse } from '../src/graph/client.js';
import { allPages, continuationOf } from '../src/graph/paging.js';
import { parsePolicy } from '../src/policy.js';
import { buildAuthStrength, observeSignIns } from '../src/services/authStrength.js';
import { buildCredentialChanges } from '../src/services/credentialChanges.js';
import { buildPrivilege } from '../src/services/privilege.js';
import { buildGuests } from '../src/services/relationships.js';
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
