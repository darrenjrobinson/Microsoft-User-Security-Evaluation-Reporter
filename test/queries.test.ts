import { describe, expect, it } from 'vitest';
import { isObjectId, isoNoMillis, odataString, queries, sanitizeSearch } from '../src/graph/queries.js';

const ID = '6e7b768e-07e2-4810-8459-485f84f8f204';

describe('query helpers', () => {
  it('validates object ids', () => {
    expect(isObjectId(ID)).toBe(true);
    expect(isObjectId('rick@contoso.com')).toBe(false);
    expect(isObjectId(`${ID}/manager`)).toBe(false);
  });

  it('escapes OData strings and search text', () => {
    expect(odataString("O'Brien")).toBe("'O''Brien'");
    expect(sanitizeSearch('a"b\\c:d   e')).toBe('a b c d e');
  });

  it('formats dates without milliseconds', () => {
    expect(isoNoMillis(new Date('2026-01-02T03:04:05.678Z'))).toBe('2026-01-02T03:04:05Z');
  });
});

describe('queries', () => {
  const now = new Date('2026-10-23T00:00:00Z');
  const param = (url: string, name: string) => new URL(url, 'https://g/').searchParams.get(name);

  it('builds a ConsistencyLevel search that cannot break out of the $search clause', () => {
    const { url, headers } = queries.searchUsers('Rick" OR "x');
    expect(headers.ConsistencyLevel).toBe('eventual');
    expect(param(url, '$search')).toBe('"displayName:Rick OR x" OR "userPrincipalName:Rick OR x" OR "mail:Rick OR x"');
  });

  it('builds the profile batch for an object id only', () => {
    const batch = queries.userProfileBatch(ID, now);
    expect(batch.map((r) => r.id)).toEqual([
      'user',
      'devices',
      'signIns',
      'sspr',
      'riskDetections',
      'riskyUser',
      'mfa',
      'authMethods',
      'roleSchedules',
      'roleAssignments',
      'roleEligibilities',
      'ownedObjects',
      'sponsorOf',
      'memberOf',
      'transitiveGroups',
      'methodAudits',
      'guestInvites',
    ]);
    expect(batch.length).toBeLessThanOrEqual(20);
    expect(batch.every((r) => r.method === 'GET' && r.url.startsWith('/'))).toBe(true);
    // every request is scoped to this user and nobody else
    expect(batch.every((r) => r.url.toLowerCase().includes(ID))).toBe(true);
    expect(param(batch[2]!.url, '$filter')).toBe(`userId eq '${ID}' and createdDateTime ge 2026-09-23T00:00:00Z`);
    expect(() => queries.userProfileBatch("x' or 1 eq 1")).toThrow();
  });

  it('scopes role, audit and membership queries to the principal', () => {
    const byId = Object.fromEntries(queries.userProfileBatch(ID, now).map((r) => [r.id, r]));
    expect(param(byId.roleSchedules!.url, '$filter')).toBe(`principalId eq '${ID}'`);
    expect(param(byId.roleSchedules!.url, '$expand')).toBe('roleDefinition');
    expect(param(byId.roleEligibilities!.url, '$filter')).toBe(`principalId eq '${ID}'`);
    expect(param(byId.methodAudits!.url, '$filter')).toBe(
      `loggedByService eq 'Authentication Methods' and targetResources/any(t:t/id eq '${ID}') and activityDateTime ge 2026-09-23T00:00:00Z`,
    );
    expect(param(byId.guestInvites!.url, '$filter')).toBe(
      `activityDisplayName eq 'Invite external user' and initiatedBy/user/id eq '${ID}' and activityDateTime ge 2026-09-23T00:00:00Z`,
    );
    expect(byId.transitiveGroups!.headers).toEqual({ ConsistencyLevel: 'eventual' });
    expect(param(byId.transitiveGroups!.url, '$count')).toBe('true');
  });

  it('builds the beta sign-in query for an object id only', () => {
    const [req] = queries.userAuthSignInsBeta(ID, now);
    expect(req!.id).toBe('authSignIns');
    expect(param(req!.url, '$filter')).toBe(`userId eq '${ID}' and createdDateTime ge 2026-09-23T00:00:00Z`);
    expect(() => queries.userAuthSignInsBeta('not-an-id')).toThrow();
  });

  it('reads tenant policies from fixed paths', () => {
    expect(queries.tenantPolicies().map((r) => r.url)).toEqual([
      '/policies/authenticationMethodsPolicy',
      '/policies/identitySecurityDefaultsEnforcementPolicy',
    ]);
  });
});
