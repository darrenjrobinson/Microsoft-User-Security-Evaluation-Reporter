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
  it('builds a ConsistencyLevel search that cannot break out of the $search clause', () => {
    const { url, headers } = queries.searchUsers('Rick" OR "x');
    expect(headers.ConsistencyLevel).toBe('eventual');
    const search = new URL(url, 'https://g/').searchParams.get('$search')!;
    expect(search).toBe('"displayName:Rick OR x" OR "userPrincipalName:Rick OR x" OR "mail:Rick OR x"');
  });

  it('builds the profile batch for an object id only', () => {
    const now = new Date('2026-10-23T00:00:00Z');
    const batch = queries.userProfileBatch(ID, now);
    expect(batch.map((r) => r.id)).toEqual(['user', 'devices', 'signIns', 'sspr', 'riskDetections', 'riskyUser', 'mfa']);
    expect(batch.every((r) => r.method === 'GET' && r.url.startsWith('/'))).toBe(true);
    const signIns = new URL(batch[2]!.url, 'https://g/').searchParams.get('$filter');
    expect(signIns).toBe(`userId eq '${ID}' and createdDateTime ge 2026-09-23T00:00:00Z`);
    expect(() => queries.userProfileBatch("x' or 1 eq 1")).toThrow();
  });
});
