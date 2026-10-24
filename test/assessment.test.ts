import { describe, expect, it } from 'vitest';
import {
  assessAdminHygiene,
  assessAuthStrength,
  assessCaPosture,
  assessCredentialChanges,
  assessGuestGovernance,
  assessMembership,
  assessMfaRegistration,
  assessOwnership,
  assessPassword,
  assessPimDrift,
  assessPrivilege,
  assessRisk,
  overallOf,
  withCredentialSignal,
  type MfaView,
} from '../src/services/assessment.js';
import type { AuthStrengthView } from '../src/services/authStrength.js';
import { buildCaPosture } from '../src/services/caPosture.js';
import type { IdentityView } from '../src/services/identity.js';
import { parsePolicy } from '../src/policy.js';
import type { PrivilegeView, RoleAssignmentView } from '../src/services/privilege.js';
import type { OwnershipView } from '../src/services/relationships.js';
import type { RiskDetectionView } from '../src/services/risk.js';
import { ok } from '../src/services/section.js';

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

const identity = (over: Partial<IdentityView> = {}): IdentityView => ({
  accountType: 'Cloud',
  isBreakGlass: false,
  isServiceAccount: false,
  isPrivileged: false,
  licensedWorkloads: [],
  ...over,
});

const auth = (over: Partial<AuthStrengthView>): AuthStrengthView => ({
  verdict: 'phishable',
  summary: '',
  phishingResistantRegistered: false,
  passwordlessCapable: false,
  methods: [],
  observed: null,
  ...over,
});

const role = (over: Partial<RoleAssignmentView>): RoleAssignmentView => ({
  roleName: 'Global Administrator',
  templateId: '62e90394-69f5-4237-9190-012177145e10',
  scope: 'Tenant',
  state: 'permanentActive',
  via: 'direct',
  groupName: '',
  endDateTime: null,
  impact: 'high',
  themes: [],
  known: true,
  pimRequired: true,
  pimDrift: false,
  ...over,
});
const privilege = (assignments: RoleAssignmentView[], over: Partial<PrivilegeView> = {}) =>
  ok<PrivilegeView>({ assignments, pimDetail: true, isPimException: false, gaps: [], ...over });

const detection = (state: string, type = 'anonymizedIPAddress') => ({ state, type }) as RiskDetectionView;
const policy = parsePolicy();

describe('assessment', () => {
  it('grades MFA registration separately from strength (none danger, B2B and service accounts info)', () => {
    expect(assessMfaRegistration(ok(mfa({})), identity()).level).toBe('good');
    expect(assessMfaRegistration(ok(mfa({ defaultMfaMethod: 'sms', userPreferredMethod: 'sms' })), identity()).level).toBe('good');
    expect(assessMfaRegistration(ok(mfa({ isMfaRegistered: false })), identity()).level).toBe('danger');
    expect(assessMfaRegistration(ok(null), identity({ accountType: 'B2B' })).level).toBe('info');
    expect(assessMfaRegistration(ok(mfa({ isMfaRegistered: false })), identity({ isServiceAccount: true })).level).toBe('info');
  });

  it('grades authentication strength, escalating phishable MFA on privileged accounts', () => {
    expect(assessAuthStrength(ok(auth({ verdict: 'phishingResistant' })), identity()).level).toBe('good');
    expect(assessAuthStrength(ok(auth({ verdict: 'phishable' })), identity()).level).toBe('warning');
    expect(assessAuthStrength(ok(auth({ verdict: 'phishable' })), identity({ isPrivileged: true })).level).toBe('danger');
    expect(assessAuthStrength(ok(auth({ verdict: 'passwordlessCapable' })), identity()).level).toBe('good');
    const stillWeak = auth({
      verdict: 'passwordlessCapable',
      observed: { total: 2, counts: { phishingResistant: 0, passwordless: 0, passwordPlusMfa: 0, passwordPlusWeakMfa: 2, singleFactor: 0 }, methods: [] },
    });
    expect(assessAuthStrength(ok(stillWeak), identity()).level).toBe('warning');
    // password + push is phishable too
    const pushOnly = auth({
      verdict: 'passwordlessCapable',
      observed: { total: 3, counts: { phishingResistant: 0, passwordless: 0, passwordPlusMfa: 3, passwordPlusWeakMfa: 0, singleFactor: 0 }, methods: [] },
    });
    expect(assessAuthStrength(ok(pushOnly), identity()).level).toBe('warning');
    expect(assessAuthStrength(ok(auth({})), identity({ accountType: 'B2B' })).level).toBe('info');
  });

  it('expects break-glass accounts to hold phishing-resistant credentials and permanent roles', () => {
    const bg = identity({ isBreakGlass: true, isPrivileged: true });
    expect(assessAuthStrength(ok(auth({ phishingResistantRegistered: true })), bg).level).toBe('good');
    expect(assessAuthStrength(ok(auth({})), bg).level).toBe('danger');
    expect(assessPrivilege(privilege([role({})]), bg).level).toBe('info');
    expect(assessCaPosture(buildCaPosture([{ status: { errorCode: 0 } }], 'beta'), bg).level).toBe('warning');
  });

  it('grades privilege exposure by impact and permanence', () => {
    expect(assessPrivilege(privilege([]), identity()).level).toBe('good');
    expect(assessPrivilege(privilege([role({})]), identity()).label).toBe('1 permanently active high-impact role');
    expect(assessPrivilege(privilege([role({ state: 'eligible' })]), identity()).level).toBe('warning');
    expect(assessPrivilege(privilege([role({ impact: 'low', state: 'permanentActive' })]), identity()).level).toBe('good');
    expect(assessPrivilege({ status: 'unavailable', reason: 'forbidden', message: '' }, identity()).level).toBe('unknown');
  });

  it('never reports a clean role inventory when a lookup failed', () => {
    const gaps = ["Eligible (PIM) roles for this user couldn't be read"];
    expect(assessPrivilege(privilege([], { gaps }), identity())).toMatchObject({ level: 'unknown', label: 'Role inventory incomplete' });
    // what was found still counts
    expect(assessPrivilege(privilege([role({})], { gaps }), identity()).level).toBe('danger');
    expect(assessPimDrift(privilege([], { gaps })).level).toBe('unknown');
    // no P2: an empty list with failed group-role discovery isn't "no roles" either
    expect(assessPimDrift(privilege([], { gaps, pimDetail: false }))).toMatchObject({ level: 'unknown', label: 'Role inventory incomplete' });
    expect(assessPimDrift(privilege([], { pimDetail: false })).level).toBe('good');
  });

  it('reports PIM drift as a separate overlay', () => {
    expect(assessPimDrift(privilege([role({ pimDrift: true })])).level).toBe('warning');
    expect(assessPimDrift(privilege([role({ pimDrift: true, state: 'timeBoundActive' })])).label).toBe('PIM required, but 1 role actively assigned');
    expect(assessPimDrift(privilege([role({ state: 'eligible' })])).level).toBe('good');
    expect(assessPimDrift(privilege([role({})], { pimDetail: false })).level).toBe('info');
    expect(assessPimDrift(privilege([role({})], { isPimException: true })).level).toBe('info');
  });

  it('treats owning a role-assignable group as privilege', () => {
    const owned = (kinds: OwnershipView['objects'][number]['kind'][]): OwnershipView => {
      const objects = kinds.map((kind, i) => ({ id: `o${i}`, displayName: `o${i}`, kind, sensitive: false }));
      const counts: OwnershipView['counts'] = {};
      for (const o of objects) counts[o.kind] = (counts[o.kind] ?? 0) + 1;
      return { objects, counts, complete: true };
    };
    expect(assessOwnership(ok(owned([]))).level).toBe('good');
    expect(assessOwnership(ok(owned(['team', 'securityGroup']))).level).toBe('info');
    expect(assessOwnership(ok(owned(['application', 'agent']))).label).toBe('Owns 1 app and 1 agent identity');
    expect(assessOwnership(ok(owned(['roleAssignableGroup']))).level).toBe('danger');
    expect(assessOwnership(ok({ ...owned(['team']), complete: false }))).toMatchObject({ level: 'warning', label: 'Owns at least 1 group (list truncated)' });
  });

  it('applies guest and membership thresholds, escalating for privileged users', () => {
    const guests = (footprint: number, complete = true) => ok({ sponsored: [], invites: [], footprint, complete, gaps: [] });
    expect(assessGuestGovernance(guests(0), identity(), policy).level).toBe('good');
    expect(assessGuestGovernance(guests(3), identity(), policy).level).toBe('info');
    expect(assessGuestGovernance(guests(12), identity(), policy).level).toBe('warning');
    expect(assessGuestGovernance(guests(12), identity({ isPrivileged: true }), policy).level).toBe('danger');
    // a lower bound can confirm a threshold is crossed, never that it isn't
    expect(assessGuestGovernance(guests(0, false), identity(), policy).level).toBe('info');
    expect(assessGuestGovernance(guests(12, false), identity(), policy).label).toBe('At least 12 guests sponsored or invited');

    const membership = (directGroups: number, exceeded: string[] = [], complete = true) =>
      ok({ directGroups, transitiveGroups: null, m365Groups: 0, adminUnits: [], directoryRoles: [], roleAssignableGroups: [], sensitiveGroups: [], exceeded, complete });
    expect(assessMembership(membership(5), identity(), policy).level).toBe('good');
    expect(assessMembership(membership(5, [], false), identity(), policy).level).toBe('info');
    expect(assessMembership(membership(90, ['x']), identity({ isPrivileged: true }), policy).level).toBe('warning');
    expect(assessMembership(membership(200, ['x']), identity({ isPrivileged: true }), policy).level).toBe('danger');
  });

  it('raises credential changes to the risk dimension only when they are strong signals', () => {
    const event = (flags: string[]) => ({ dateTime: '', activity: 'Admin registered security info', initiatedBy: '', bySelf: false, source: 'audit' as const, flags });
    const suspicious = ok({ events: [], suspiciousDetections: [detection('atRisk', 'suspiciousCredentialAddition')] });
    expect(assessCredentialChanges(suspicious, identity()).level).toBe('danger');
    expect(assessCredentialChanges(ok({ events: [event(['x'])], suspiciousDetections: [] }), identity()).level).toBe('warning');
    expect(assessCredentialChanges(ok({ events: [event(['x'])], suspiciousDetections: [] }), identity({ isPrivileged: true })).level).toBe('danger');
    expect(assessCredentialChanges(ok({ events: [event([])], suspiciousDetections: [] }), identity()).level).toBe('info');

    const quietRisk = { level: 'good' as const, label: '' };
    expect(withCredentialSignal(quietRisk, { level: 'danger', label: '' }).level).toBe('warning');
    expect(withCredentialSignal(quietRisk, { level: 'warning', label: '' }).level).toBe('good');
    // no P2: Identity Protection is unavailable, but the persistence evidence still counts
    expect(withCredentialSignal({ level: 'unknown', label: '' }, { level: 'danger', label: '' }).level).toBe('warning');
  });

  it('flags privileged daily-driver accounts', () => {
    const admin = identity({ isPrivileged: true, licensedWorkloads: ['Mailbox'] });
    const recoveryView = { phoneMethods: 1, emailMethod: false, smsSignIn: false, activeTap: false, weakPaths: [] };
    const recovery = ok(recoveryView);
    expect(assessAdminHygiene(identity(), ok(auth({})), privilege([]), recovery).level).toBe('info');
    expect(assessAdminHygiene(admin, ok(auth({ verdict: 'phishingResistant' })), privilege([]), ok({ ...recoveryView, phoneMethods: 0 })).level).toBe('warning');
    expect(assessAdminHygiene(admin, ok(auth({})), privilege([role({})]), recovery).level).toBe('danger');
  });

  it('interprets Conditional Access outcomes', () => {
    const signIn = (requirement: string, ca: string, errorCode = 0) => ({ authenticationRequirement: requirement, conditionalAccessStatus: ca, status: { errorCode } });
    expect(assessCaPosture(buildCaPosture([signIn('multiFactorAuthentication', 'success')], 'v1.0'), identity()).level).toBe('good');
    expect(assessCaPosture(buildCaPosture([signIn('singleFactorAuthentication', 'notApplied')], 'v1.0'), identity()).level).toBe('warning');
    const failures = Array(3).fill(signIn('multiFactorAuthentication', 'failure', 53003));
    const view = buildCaPosture(failures, 'v1.0');
    expect(view).toMatchObject({ caFailures: 3, blockedByPolicy: 3 });
    expect(assessCaPosture(view, identity()).level).toBe('warning');
    // failures alone don't show MFA is enforced
    const failedOnly = buildCaPosture([signIn('multiFactorAuthentication', 'success', 50126)], 'v1.0');
    expect(assessCaPosture(failedOnly, identity())).toMatchObject({ level: 'info', label: 'No successful interactive sign-ins (1 failed)' });
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
    const c = (level: 'good' | 'warning' | 'danger') => ({ level, label: level });
    expect(overallOf({ mfa: c('good'), risk: c('good'), password: c('good') }).level).toBe('good');
    expect(overallOf({ mfa: c('warning'), risk: c('good'), password: c('good') }).level).toBe('warning');
    expect(overallOf({ mfa: c('good'), risk: c('good'), password: c('danger') }).level).toBe('warning');
    expect(overallOf({ mfa: c('danger'), risk: c('good'), password: c('good') }).level).toBe('danger');
  });

  it('adds the new dimensions to the same sum and explains the verdict', () => {
    const c = (level: 'good' | 'warning' | 'danger', label: string = level) => ({ level, label });
    const overall = overallOf({
      risk: c('danger', 'High user risk'),
      privilege: c('danger', '1 permanently active high-impact role'),
      authStrength: c('warning', 'MFA only – phishable methods'),
      guests: c('warning', '12 guests'),
      membership: c('good'),
    });
    expect(overall).toMatchObject({ level: 'danger', score: 7.5 });
    expect(overall.reasons).toEqual(['High user risk', '1 permanently active high-impact role', 'MFA only – phishable methods']);
    expect(overallOf({ guests: c('warning'), membership: c('warning') })).toMatchObject({ level: 'warning', score: 1 });
  });
});
