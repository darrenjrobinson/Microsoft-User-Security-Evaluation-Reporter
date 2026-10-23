import { describe, expect, it } from 'vitest';
import type { MfaView } from '../src/services/assessment.js';
import { buildAuthStrength, buildRecovery, classifySignIn, observeSignIns, toAuthMethod } from '../src/services/authStrength.js';
import { ok } from '../src/services/section.js';

const step = (authenticationMethod: string, succeeded = true) => ({ authenticationMethod, succeeded });
const signIn = (...methods: string[]) => ({ status: { errorCode: 0 }, isInteractive: true, authenticationDetails: methods.map((m) => step(m)) });
const method = (type: string, extra: Record<string, unknown> = {}) => ({ '@odata.type': `#microsoft.graph.${type}AuthenticationMethod`, id: type, ...extra });

const registration = (over: Partial<MfaView> = {}): MfaView => ({
  isMfaRegistered: true,
  isMfaCapable: true,
  isPasswordlessCapable: false,
  isSsprRegistered: true,
  defaultMfaMethod: 'sms',
  userPreferredMethod: 'sms',
  methodsRegistered: ['mobilePhone'],
  systemPreferredMethods: [],
  lastUpdatedDateTime: null,
  ...over,
});
const unavailable = { status: 'unavailable', reason: 'error', message: 'beta unavailable' } as const;

describe('authentication strength', () => {
  it('classifies sign-ins by their successful steps', () => {
    expect(classifySignIn([step('Windows Hello for Business')])).toBe('phishingResistant');
    expect(classifySignIn([step('Passkey (device-bound)')])).toBe('phishingResistant');
    expect(classifySignIn([step('Password'), step('Text message')])).toBe('passwordPlusWeakMfa');
    expect(classifySignIn([step('Password'), step('Mobile app notification')])).toBe('passwordPlusMfa');
    expect(classifySignIn([step('Password')])).toBe('singleFactor');
    expect(classifySignIn([step('Temporary Access Pass')])).toBe('passwordless');
    // token reuse and failed steps are not evidence
    expect(classifySignIn([step('Previously satisfied')])).toBeNull();
    expect(classifySignIn([step('Password'), step('FIDO2 security key', false)])).toBe('singleFactor');
  });

  it('counts only successful interactive sign-ins', () => {
    const observed = observeSignIns([
      signIn('Windows Hello for Business'),
      signIn('Password', 'Text message'),
      { ...signIn('Password'), status: { errorCode: 50126 } },
      { ...signIn('Password'), isInteractive: false },
    ]);
    expect(observed.total).toBe(2);
    expect(observed.counts).toMatchObject({ phishingResistant: 1, passwordPlusWeakMfa: 1 });
    expect(observed.methods[0]).toEqual({ method: 'Windows Hello for Business', count: 1 });
  });

  it('never claims phishing-resistant from registration alone', () => {
    const methods = ok([method('password'), method('fido2', { displayName: 'YubiKey' })].map(toAuthMethod));
    const noEvidence = buildAuthStrength(ok(registration({ isPasswordlessCapable: true })), methods, unavailable);
    expect(noEvidence.status === 'ok' && noEvidence.data.verdict).toBe('passwordlessCapable');
    expect(noEvidence.status === 'ok' && noEvidence.data.summary).toMatch(/usage is unconfirmed/);

    const weakUsage = buildAuthStrength(ok(registration()), methods, ok(observeSignIns([signIn('Password', 'Text message')])));
    expect(weakUsage.status === 'ok' && weakUsage.data.verdict).toBe('passwordlessCapable');
    expect(weakUsage.status === 'ok' && weakUsage.data.summary).toBe(
      'Registered for passwordless authentication with Passkey (FIDO2), but recent sign-ins still show reliance on password + SMS/voice.',
    );

    const strongUsage = buildAuthStrength(ok(registration()), methods, ok(observeSignIns([signIn('FIDO2 security key')])));
    expect(strongUsage.status === 'ok' && strongUsage.data.verdict).toBe('phishingResistant');
  });

  it('distinguishes phishable MFA from no strong method at all', () => {
    const phishable = buildAuthStrength(ok(registration()), ok([method('phone')].map(toAuthMethod)), ok(observeSignIns([])));
    expect(phishable.status === 'ok' && phishable.data.verdict).toBe('phishable');
    const none = buildAuthStrength(ok(registration({ isMfaRegistered: false })), ok([method('temporaryAccessPass')].map(toAuthMethod)), unavailable);
    expect(none.status === 'ok' && none.data.verdict).toBe('none');
  });

  it('lists weak recovery paths', () => {
    const raw = [
      method('phone', { phoneType: 'mobile', smsSignInState: 'ready' }),
      method('phone', { phoneType: 'office' }),
      method('email', { emailAddress: 'a@b.c' }),
      method('temporaryAccessPass', { isUsable: true }),
    ];
    const recovery = buildRecovery(ok(raw.map(toAuthMethod)), raw);
    expect(recovery.status === 'ok' && recovery.data).toMatchObject({ phoneMethods: 2, smsSignIn: true, emailMethod: true, activeTap: true });
    expect(recovery.status === 'ok' && recovery.data.weakPaths).toHaveLength(4);
  });
});
