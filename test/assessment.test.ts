import { describe, expect, it } from 'vitest';
import { assessMfa, assessPassword, assessRisk, overallOf, type MfaView } from '../src/services/assessment.js';
import { ok } from '../src/services/section.js';
import type { RiskDetectionView } from '../src/services/risk.js';

const mfa = (over: Partial<MfaView>): MfaView => ({
  isMfaRegistered: true,
  isMfaCapable: true,
  isPasswordlessCapable: false,
  isSsprRegistered: true,
  defaultMfaMethod: 'push',
  userPreferredMethod: 'push',
  methodsRegistered: ['microsoftAuthenticatorPush'],
  systemPreferredMethods: [],
  lastUpdatedDateTime: null,
  ...over,
});

const detection = (state: string, type = 'anonymizedIPAddress') => ({ state, type }) as RiskDetectionView;

describe('assessment', () => {
  it('grades MFA like the original (Authenticator good, SMS warning, none danger, B2B info)', () => {
    expect(assessMfa(ok(mfa({})), 'Cloud').level).toBe('good');
    expect(assessMfa(ok(mfa({ defaultMfaMethod: 'sms', userPreferredMethod: 'sms' })), 'Cloud').level).toBe('warning');
    expect(assessMfa(ok(mfa({ isMfaRegistered: false })), 'Cloud').level).toBe('danger');
    expect(assessMfa(ok(null), 'B2B').level).toBe('info');
  });

  it('grades risk by active detection count', () => {
    expect(assessRisk(ok([]), ok(null)).level).toBe('good');
    expect(assessRisk(ok([detection('remediated')]), ok(null)).level).toBe('good');
    expect(assessRisk(ok([detection('atRisk')]), ok(null)).level).toBe('warning');
    expect(assessRisk(ok(Array(4).fill(detection('atRisk'))), ok(null)).level).toBe('danger');
  });

  it('flags leaked credentials ahead of HIBP', () => {
    const hibpClean = ok({ account: 'a@b.c', breaches: [], pasteCount: 0 });
    expect(assessPassword(hibpClean, ok([])).level).toBe('good');
    expect(assessPassword(hibpClean, ok([detection('atRisk', 'leakedCredentials')])).level).toBe('danger');
  });

  it('sums the original weights into an overall verdict', () => {
    const c = (level: 'good' | 'warning' | 'danger') => ({ level, label: '' });
    expect(overallOf({ mfa: c('good'), risk: c('good'), password: c('good') }).level).toBe('good');
    expect(overallOf({ mfa: c('warning'), risk: c('good'), password: c('good') }).level).toBe('warning');
    expect(overallOf({ mfa: c('good'), risk: c('good'), password: c('danger') }).level).toBe('warning');
    expect(overallOf({ mfa: c('danger'), risk: c('good'), password: c('good') }).level).toBe('danger');
  });
});
