import type { Policy } from '../policy.js';
import type { AuthStrengthView, RecoveryView } from './authStrength.js';
import type { CaPostureView } from './caPosture.js';
import type { CredentialChangesView } from './credentialChanges.js';
import type { HibpView } from './hibp.js';
import type { IdentityView } from './identity.js';
import type { PrivilegeView } from './privilege.js';
import type { GuestGovernanceView, MembershipView, OwnershipView } from './relationships.js';
import type { RiskDetectionView } from './risk.js';
import type { Section } from './section.js';

export type Level = 'good' | 'warning' | 'danger' | 'info' | 'unknown';

export interface Check {
  level: Level;
  label: string;
}

export interface MfaView {
  isMfaRegistered: boolean;
  isMfaCapable: boolean;
  isPasswordlessCapable: boolean;
  isSsprRegistered: boolean;
  defaultMfaMethod: string;
  userPreferredMethod: string;
  methodsRegistered: string[];
  systemPreferredMethods: string[];
  lastUpdatedDateTime: string | null;
}

export interface RiskyUserView {
  riskLevel: string;
  riskState: string;
  riskLastUpdatedDateTime: string | null;
}

/** Checks that feed the overall score */
export interface WeightedChecks {
  mfa: Check;
  authStrength: Check;
  risk: Check;
  password: Check;
  privilege: Check;
  guests: Check;
  membership: Check;
}

/** Shown alongside the score but not weighted: policy drift and investigation overlays */
export interface OverlayChecks {
  pimDrift: Check;
  ownership: Check;
  recovery: Check;
  credentialChanges: Check;
  adminHygiene: Check;
  caPosture: Check;
  devices: Check;
  sspr: Check;
}

export interface Assessment extends WeightedChecks, OverlayChecks {
  overall: { level: Exclude<Level, 'info' | 'unknown'>; label: string; score: number; reasons: string[] };
}

const good = (label: string): Check => ({ level: 'good', label });
const warning = (label: string): Check => ({ level: 'warning', label });
const danger = (label: string): Check => ({ level: 'danger', label });
const info = (label: string): Check => ({ level: 'info', label });
const unknown = (label: string): Check => ({ level: 'unknown', label });
const plural = (n: number, word: string, many = `${word}s`) => `${n} ${n === 1 ? word : many}`;

const ACTIVE_RISK_STATES = new Set(['atRisk', 'confirmedCompromised']);

export function assessRisk(detections: Section<RiskDetectionView[]>, riskyUser: Section<RiskyUserView | null>): Check {
  if (detections.status !== 'ok') return unknown('Risk data unavailable');
  const active = detections.data.filter((d) => ACTIVE_RISK_STATES.has(d.state)).length;
  const user = riskyUser.status === 'ok' ? riskyUser.data : null;
  if (user?.riskState === 'confirmedCompromised' || user?.riskLevel === 'high' || active > 3) {
    return danger('User risk events to review');
  }
  if (active > 0 || (user && ACTIVE_RISK_STATES.has(user.riskState))) return warning('User risk events to review');
  // No active detections, but the user's own risk state couldn't be read: don't call that clean
  if (riskyUser.status !== 'ok') return unknown('User risk state unavailable');
  return good('No active risk events found');
}

/** MFA registration only – how strong those methods are is assessAuthStrength's job. */
export function assessMfaRegistration(mfa: Section<MfaView | null>, identity: Pick<IdentityView, 'accountType' | 'isServiceAccount'>): Check {
  if (identity.accountType === 'B2B') return info('B2B user – MFA is enforced by their home tenant');
  if (identity.isServiceAccount) return info('Service account – per-user MFA checks are out of scope');
  if (mfa.status !== 'ok' || !mfa.data) return unknown('MFA registration unavailable');
  if (!mfa.data.isMfaRegistered) return danger('Not registered for MFA');
  return good(`Registered for MFA (${plural(mfa.data.methodsRegistered.length, 'method')})`);
}

export function assessAuthStrength(auth: Section<AuthStrengthView>, identity: IdentityView): Check {
  if (identity.accountType === 'B2B') return info('B2B user – authentication methods are managed by their home tenant');
  if (identity.isServiceAccount) return info('Service account – authentication strength is out of scope');
  if (auth.status !== 'ok') return unknown('Authentication strength unavailable');
  const a = auth.data;
  if (identity.isBreakGlass) {
    return a.phishingResistantRegistered
      ? good('Emergency access account protected by phishing-resistant credentials')
      : danger('Emergency access account has no phishing-resistant credential');
  }
  // Any sign-in without a phishing-resistant step – password + push and OATH codes are phishable too
  const phishableObserved = !!a.observed && a.observed.total - a.observed.counts.phishingResistant > 0;
  switch (a.verdict) {
    case 'phishingResistant':
      return good('Phishing-resistant sign-ins observed');
    case 'passwordlessCapable':
      return phishableObserved ? warning('Passwordless-capable, but still signing in with phishable methods') : good('Passwordless-capable (usage not confirmed)');
    case 'phishable':
      return identity.isPrivileged ? danger('Privileged account relies on phishable MFA') : warning('MFA only – phishable methods');
    case 'none':
      return identity.isPrivileged ? danger('Privileged account has no strong authentication') : warning('No strong authentication method');
  }
}

export function assessRecovery(recovery: Section<RecoveryView>, auth: Section<AuthStrengthView>): Check {
  if (recovery.status !== 'ok') return unknown('Recovery methods unavailable');
  const r = recovery.data;
  if (r.activeTap) return warning('A Temporary Access Pass is active');
  if (r.weakPaths.length === 0) return good('No weak recovery paths');
  const strong = auth.status === 'ok' && auth.data.phishingResistantRegistered;
  return strong ? warning('Strong sign-in, but weaker recovery paths remain') : info(plural(r.weakPaths.length, 'weak recovery path'));
}

export function assessPassword(hibp: Section<HibpView>, detections: Section<RiskDetectionView[]>): Check {
  const leaked = detections.status === 'ok' && detections.data.some((d) => d.type === 'leakedCredentials');
  if (leaked) return danger('Entra ID Protection found leaked credentials');
  if (hibp.status !== 'ok') return unknown(hibp.reason === 'disabled' ? 'HIBP check not configured' : 'HIBP check unavailable');
  const withPasswords = hibp.data.breaches.filter((b) => b.includesPasswords).length;
  if (withPasswords > 0) return danger(`Email found in ${withPasswords} breach(es) exposing passwords`);
  if (hibp.data.breaches.length > 0 || hibp.data.pasteCount > 0) return warning('Email found in breaches (no passwords exposed)');
  return good('Not found in Have I Been Pwned');
}

/** "Global Administrator, Exchange Administrator +2 more" – keeps a check label to one readable line */
function roleNames(roles: { roleName: string }[]): string {
  const names = [...new Set(roles.map((r) => r.roleName))];
  return names.length > 2 ? `${names.slice(0, 2).join(', ')} +${names.length - 2} more` : names.join(', ');
}

export function assessPrivilege(privilege: Section<PrivilegeView>, identity: IdentityView): Check {
  if (privilege.status !== 'ok') return unknown('Role assignments unavailable');
  const { assignments: roles, gaps } = privilege.data;
  const permanentHigh = roles.filter((r) => r.impact === 'high' && r.state === 'permanentActive');
  if (identity.isBreakGlass) return info(`Emergency access account – ${plural(permanentHigh.length, 'permanent high-impact role')} expected`);
  if (permanentHigh.length > 0) return danger(`${plural(permanentHigh.length, 'permanently active high-impact role')} (${roleNames(permanentHigh)})`);
  const high = roles.filter((r) => r.impact === 'high');
  if (high.length > 0) return warning(`${plural(high.length, 'high-impact role')} through PIM or time-bound (${roleNames(high)})`);
  const activeMedium = roles.filter((r) => r.impact === 'medium' && r.state !== 'eligible');
  if (activeMedium.length > 0) return warning(`${plural(activeMedium.length, 'active medium-impact role')} (${roleNames(activeMedium)})`);
  // Nothing risky found – but only say so when every lookup succeeded
  if (gaps.length > 0) return unknown('Role inventory incomplete');
  return good(roles.length === 0 ? 'No Entra roles assigned' : 'Only low-impact or eligible roles');
}

export function assessPimDrift(privilege: Section<PrivilegeView>): Check {
  if (privilege.status !== 'ok') return unknown('Role assignments unavailable');
  const p = privilege.data;
  if (!p.pimDetail) {
    if (p.assignments.length) return info('PIM not available – every role is permanently assigned');
    // An empty list is only clear when every lookup (including group-held roles) succeeded
    return p.gaps.length > 0 ? unknown('Role inventory incomplete') : good('No Entra roles assigned');
  }
  const drift = p.assignments.filter((a) => a.pimDrift);
  if (drift.length > 0) return warning(`PIM required, but ${plural(drift.length, 'role')} actively assigned`);
  if (p.gaps.length > 0) return unknown('Role inventory incomplete');
  if (p.isPimException && p.assignments.some((a) => a.pimRequired)) return info('Approved exception to the PIM policy');
  return good(p.assignments.some((a) => a.pimRequired) ? 'Required-PIM roles are PIM-governed' : 'No roles that require PIM');
}

export function assessOwnership(ownership: Section<OwnershipView>): Check {
  if (ownership.status !== 'ok') return unknown('Owned objects unavailable');
  const { objects, counts, complete } = ownership.data;
  if (objects.length === 0) return good('Owns no apps, agents or groups');
  const roleGroups = counts.roleAssignableGroup ?? 0;
  const agents = counts.agent ?? 0;
  const apps = (counts.application ?? 0) + (counts.servicePrincipal ?? 0);
  // An owner of a role-assignable group can add themselves – and so hold its roles
  if (roleGroups > 0) return danger(`Owns ${plural(roleGroups, 'role-assignable group')}`);
  if (objects.some((o) => o.sensitive)) return danger('Owns a sensitive group');
  if (apps + agents > 0) {
    return warning(`Owns ${[apps && plural(apps, 'app'), agents && plural(agents, 'agent identity', 'agent identities')].filter(Boolean).join(' and ')}`);
  }
  if (!complete) return warning(`Owns at least ${plural(objects.length, 'group')} (list truncated)`);
  return objects.length > 20 ? warning(`Owns ${objects.length} groups`) : info(`Owns ${plural(objects.length, 'group')}`);
}

export function assessGuestGovernance(guests: Section<GuestGovernanceView>, identity: IdentityView, policy: Policy): Check {
  if (guests.status !== 'ok') return unknown('Guest relationships unavailable');
  const { footprint: n, complete } = guests.data;
  const t = policy.guestThresholds;
  // An incomplete footprint is a lower bound: it can confirm a threshold is crossed, never that it isn't
  const atLeast = complete ? '' : 'at least ';
  if (n >= t.danger || (identity.isPrivileged && n >= t.warning)) return danger(`Large guest footprint: ${atLeast}${n} guests sponsored or invited`);
  if (n >= t.warning) return warning(`${complete ? '' : 'At least '}${n} guests sponsored or invited`);
  if (!complete) return info(n === 0 ? 'No guest invitations found; sponsorships not checked' : `At least ${plural(n, 'guest')} sponsored or invited`);
  if (n === 0) return good('No guests sponsored or invited');
  return info(`${plural(n, 'guest')} sponsored or invited`);
}

export function assessMembership(membership: Section<MembershipView>, identity: IdentityView, policy: Policy): Check {
  if (membership.status !== 'ok') return unknown('Group memberships unavailable');
  const m = membership.data;
  const t = policy.membershipThresholds;
  if (m.exceeded.length === 0) {
    if (!m.complete) return info(`At least ${plural(m.directGroups, 'group')} (list truncated)`);
    return good(`${plural(m.directGroups, 'group')}${m.transitiveGroups !== null ? ` (${m.transitiveGroups} including nested)` : ''}`);
  }
  const extreme = m.directGroups > 2 * t.directGroups || (m.transitiveGroups ?? 0) > 2 * t.transitiveGroups;
  if (extreme && identity.isPrivileged) return danger('Extreme membership sprawl on a privileged account');
  return warning('Broad membership footprint to review');
}

export function assessCredentialChanges(changes: Section<CredentialChangesView>, identity: IdentityView): Check {
  if (changes.status !== 'ok') return unknown('Credential change history unavailable');
  const c = changes.data;
  if (c.suspiciousDetections.length > 0) return danger('Microsoft flagged a suspicious credential addition');
  const flagged = c.events.filter((e) => e.flags.length > 0).length;
  if (flagged > 0) {
    const label = `${plural(flagged, 'credential change')} to investigate`;
    return identity.isPrivileged ? danger(label) : warning(label);
  }
  if (c.events.length > 0) return info(`${plural(c.events.length, 'security info change')} in 30 days`);
  return good('No recent authentication method changes');
}

export function assessAdminHygiene(identity: IdentityView, auth: Section<AuthStrengthView>, privilege: Section<PrivilegeView>, recovery: Section<RecoveryView>): Check {
  if (identity.isBreakGlass) return info('Emergency access account');
  if (!identity.isPrivileged) return info('Not a privileged account');
  const signals: string[] = [];
  if (identity.licensedWorkloads.length > 0) signals.push(`daily-driver account (${identity.licensedWorkloads.join(', ')})`);
  if (auth.status === 'ok' && auth.data.verdict !== 'phishingResistant') signals.push('not using phishing-resistant sign-in');
  if (privilege.status === 'ok' && privilege.data.assignments.some((a) => a.impact === 'high' && a.state === 'permanentActive')) signals.push('permanent high-impact roles');
  if (recovery.status === 'ok' && recovery.data.phoneMethods > 0) signals.push('phone fallback registered');
  if (signals.length === 0) return good('Looks like a dedicated admin identity');
  const label = signals[0]![0]!.toUpperCase() + signals.join('; ').slice(1);
  return signals.length >= 3 ? danger(label) : warning(label);
}

export function assessCaPosture(ca: CaPostureView | null, identity: IdentityView): Check {
  if (!ca) return unknown('Sign-in data unavailable');
  if (identity.isBreakGlass) {
    return ca.total > 0 ? warning(`Emergency access account signed in ${plural(ca.total, 'time')} – confirm it was authorised`) : good('Emergency access account unused in 30 days');
  }
  if (ca.total === 0) return info('No recent interactive sign-ins');
  if (ca.unprotected > 0) return warning(`${plural(ca.unprotected, 'single-factor sign-in')} with no Conditional Access applied`);
  if (ca.caFailures >= 3) return warning(`${ca.caFailures} Conditional Access failures`);
  if (ca.singleFactor > 0) return info(`${plural(ca.singleFactor, 'single-factor sign-in')} allowed by policy`);
  // Failed sign-ins alone say nothing about whether MFA is enforced
  if (ca.mfaSatisfied === 0) return info(`No successful interactive sign-ins (${ca.total} failed)`);
  return good('MFA enforced on recent sign-ins');
}

export function assessDevices(devices: Section<{ trustType: string }[]>): Check {
  if (devices.status !== 'ok') return unknown('Device data unavailable');
  if (devices.data.length === 0) return info('No registered devices');
  const joined = devices.data.some((d) => d.trustType === 'AzureAd' || d.trustType === 'ServerAd');
  return joined ? good('Has an Entra joined device') : warning('No Entra joined devices – only registered');
}

export function assessSspr(events: Section<{ result: string }[]>): Check {
  if (events.status !== 'ok') return unknown('Password reset activity unavailable');
  const failures = events.data.filter((e) => e.result === 'failure').length;
  if (failures >= 3) return warning(`${failures} failed password resets in 30 days`);
  return good(`${events.data.length} password reset event(s) in 30 days`);
}

/** A strong persistence signal raises the risk dimension even when Identity Protection hasn't (yet). */
export function withCredentialSignal(risk: Check, credentialChanges: Check): Check {
  // Also when Identity Protection is unavailable (no P2): the persistence evidence stands on its own
  if (credentialChanges.level === 'danger' && (risk.level === 'good' || risk.level === 'unknown')) return warning('Suspicious credential change to review');
  return risk;
}

// The original "User Secure Score Risk Profile" summed MFA (warning 1, danger 3), risk (1, 3) and pwned
// password (danger 2.5). The newer dimensions join the same sum; overlays are displayed but not weighted.
// 0 = great, ≤2.5 = could be improved, otherwise attention.
const WEIGHTS: Record<keyof WeightedChecks, { warning: number; danger: number }> = {
  mfa: { warning: 1, danger: 3 },
  risk: { warning: 1, danger: 3 },
  password: { warning: 1, danger: 2.5 },
  authStrength: { warning: 1, danger: 2 },
  privilege: { warning: 1, danger: 3 },
  guests: { warning: 0.5, danger: 1.5 },
  membership: { warning: 0.5, danger: 1 },
};

export function overallOf(checks: Partial<WeightedChecks>): Assessment['overall'] {
  const contributions = (Object.keys(WEIGHTS) as (keyof WeightedChecks)[])
    .map((key) => {
      const check = checks[key];
      const level = check?.level;
      const weight = level === 'warning' || level === 'danger' ? WEIGHTS[key][level] : 0;
      return { weight, label: check?.label ?? '' };
    })
    .filter((c) => c.weight > 0)
    .sort((a, b) => b.weight - a.weight);
  const score = contributions.reduce((sum, c) => sum + c.weight, 0);
  const reasons = contributions.slice(0, 3).map((c) => c.label);
  if (score === 0) return { level: 'good', label: 'Awesome. Great profile', score, reasons };
  if (score <= 2.5) return { level: 'warning', label: 'OK, but could be improved', score, reasons };
  return { level: 'danger', label: 'Immediate attention required', score, reasons };
}
