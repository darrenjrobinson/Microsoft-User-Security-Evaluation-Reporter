import { describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config.js';
import { parsePolicy } from '../src/policy.js';

const GA = '62e90394-69f5-4237-9190-012177145e10';
const USER_ADMIN = 'fe930be7-5e62-47db-91af-98c3a49a38b1';
const BG = 'C0FFEE00-B6A5-4C1D-9E8F-000000000911';

describe('policy', () => {
  it('defaults required-PIM roles to the high-impact catalog and fills thresholds', () => {
    const p = parsePolicy();
    expect(p.requiredPimRoles).toContain(GA);
    expect(p.requiredPimRoles).toContain(USER_ADMIN);
    expect(p.membershipThresholds).toEqual({ directGroups: 75, transitiveGroups: 200, sensitiveGroups: 3 });
    expect(p.guestThresholds).toEqual({ warning: 10, danger: 50 });
    expect(p.breakGlassAccounts).toEqual([]);
  });

  it('parses overrides and normalises ids and UPNs to lower case', () => {
    const p = parsePolicy(
      JSON.stringify({
        requiredPimRoles: [GA],
        breakGlassAccounts: [BG, 'EA02@Contoso.onmicrosoft.com'],
        membershipThresholds: { directGroups: 10 },
      }),
    );
    expect(p.requiredPimRoles).toEqual([GA]);
    expect(p.breakGlassAccounts).toEqual([BG.toLowerCase(), 'ea02@contoso.onmicrosoft.com']);
    expect(p.membershipThresholds).toEqual({ directGroups: 10, transitiveGroups: 200, sensitiveGroups: 3 });
  });

  it('rejects invalid JSON, unknown keys and non-GUID role ids with a useful message', () => {
    expect(() => parsePolicy('{nope')).toThrow('POLICY_JSON is not valid JSON');
    expect(() => parsePolicy(JSON.stringify({ requiredPimRoles: ['Global Administrator'] }))).toThrow(/requiredPimRoles\.0/);
    expect(() => parsePolicy(JSON.stringify({ breakGlass: [] }))).toThrow(/POLICY_JSON is invalid/);
  });

  it('is loaded as part of the app config', () => {
    const config = loadConfig({ NODE_ENV: 'test', POLICY_JSON: JSON.stringify({ pimExceptions: [BG] }) });
    expect(config.policy.pimExceptions).toEqual([BG.toLowerCase()]);
    expect(() => loadConfig({ NODE_ENV: 'test', POLICY_JSON: '[]' })).toThrow();
  });
});
