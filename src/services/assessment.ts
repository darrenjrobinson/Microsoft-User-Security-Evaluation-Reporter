import type { HibpView } from './hibp.js';
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

export interface Assessment {
  overall: { level: Exclude<Level, 'info' | 'unknown'>; label: string; score: number };
  risk: Check;
  password: Check;
  mfa: Check;
  devices: Check;
  sspr: Check;
}

// Methods the original app treated as "good" (an authenticator app rather than SMS/voice)
const STRONG_METHODS = new Set([
  'push',
  'oath',
  'microsoftAuthenticatorPush',
  'microsoftAuthenticatorPasswordless',
  'softwareOneTimePasscode',
  'hardwareOneTimePasscode',
  'fido2',
  'passKeyDeviceBound',
  'passKeyDeviceBoundAuthenticator',
  'passKeyDeviceBoundWindowsHello',
  'windowsHelloForBusiness',
]);
const WEAK_METHODS = new Set(['sms', 'voiceMobile', 'voiceAlternateMobile', 'voiceOffice', 'mobilePhone', 'email']);

const ACTIVE_RISK_STATES = new Set(['atRisk', 'confirmedCompromised']);

export function assessRisk(detections: Section<RiskDetectionView[]>, riskyUser: Section<RiskyUserView | null>): Check {
  if (detections.status !== 'ok') return { level: 'unknown', label: 'Risk data unavailable' };
  const active = detections.data.filter((d) => ACTIVE_RISK_STATES.has(d.state)).length;
  const user = riskyUser.status === 'ok' ? riskyUser.data : null;
  if (user?.riskState === 'confirmedCompromised' || user?.riskLevel === 'high' || active > 3) {
    return { level: 'danger', label: 'User risk events to review' };
  }
  if (active > 0 || (user && ACTIVE_RISK_STATES.has(user.riskState))) {
    return { level: 'warning', label: 'User risk events to review' };
  }
  return { level: 'good', label: 'No active risk events found' };
}

export function assessMfa(mfa: Section<MfaView | null>, accountType: string): Check {
  if (accountType === 'B2B') return { level: 'info', label: 'B2B user – MFA is enforced by their home tenant' };
  if (mfa.status !== 'ok' || !mfa.data) return { level: 'unknown', label: 'MFA registration unavailable' };
  const m = mfa.data;
  if (!m.isMfaRegistered) return { level: 'danger', label: 'Not registered for MFA' };
  const primary = [m.userPreferredMethod, m.defaultMfaMethod, ...m.systemPreferredMethods].find(
    (x) => x && x !== 'none',
  );
  if (m.isPasswordlessCapable || (primary && STRONG_METHODS.has(primary))) {
    return { level: 'good', label: 'MFA registered with a strong primary method' };
  }
  if (!primary || WEAK_METHODS.has(primary)) {
    return { level: 'warning', label: 'MFA registered, but primary method is SMS/voice' };
  }
  return { level: 'good', label: 'MFA registered' };
}

export function assessPassword(hibp: Section<HibpView>, detections: Section<RiskDetectionView[]>): Check {
  const leaked = detections.status === 'ok' && detections.data.some((d) => d.type === 'leakedCredentials');
  if (leaked) return { level: 'danger', label: 'Entra ID Protection found leaked credentials' };
  if (hibp.status !== 'ok') {
    return { level: 'unknown', label: hibp.reason === 'disabled' ? 'HIBP check not configured' : 'HIBP check unavailable' };
  }
  const withPasswords = hibp.data.breaches.filter((b) => b.includesPasswords).length;
  if (withPasswords > 0) return { level: 'danger', label: `Email found in ${withPasswords} breach(es) exposing passwords` };
  if (hibp.data.breaches.length > 0 || hibp.data.pasteCount > 0) {
    return { level: 'warning', label: 'Email found in breaches (no passwords exposed)' };
  }
  return { level: 'good', label: 'Not found in Have I Been Pwned' };
}

export function assessDevices(devices: Section<{ trustType: string }[]>): Check {
  if (devices.status !== 'ok') return { level: 'unknown', label: 'Device data unavailable' };
  if (devices.data.length === 0) return { level: 'info', label: 'No registered devices' };
  const joined = devices.data.some((d) => d.trustType === 'AzureAd' || d.trustType === 'ServerAd');
  return joined
    ? { level: 'good', label: 'Has an Entra joined device' }
    : { level: 'warning', label: 'No Entra joined devices – only registered' };
}

export function assessSspr(events: Section<{ result: string }[]>): Check {
  if (events.status !== 'ok') return { level: 'unknown', label: 'Password reset activity unavailable' };
  const failures = events.data.filter((e) => e.result === 'failure').length;
  if (failures >= 3) return { level: 'warning', label: `${failures} failed password resets in 30 days` };
  return { level: 'good', label: `${events.data.length} password reset event(s) in 30 days` };
}

// The original "User Secure Score Risk Profile": MFA (warning 1, danger 3), risk (warning 1, danger 3)
// and pwned password (danger 2.5) are summed. 0 = great, ≤2.5 = could be improved, otherwise attention.
const WEIGHTS = {
  mfa: { warning: 1, danger: 3 },
  risk: { warning: 1, danger: 3 },
  password: { warning: 1, danger: 2.5 },
} as const;

export function overallOf(checks: Pick<Assessment, 'mfa' | 'risk' | 'password'>): Assessment['overall'] {
  const weight = (key: keyof typeof WEIGHTS) => {
    const level = checks[key].level;
    return level === 'warning' || level === 'danger' ? WEIGHTS[key][level] : 0;
  };
  const score = weight('mfa') + weight('risk') + weight('password');
  if (score === 0) return { level: 'good', label: 'Awesome. Great profile', score };
  if (score <= 2.5) return { level: 'warning', label: 'OK, but could be improved', score };
  return { level: 'danger', label: 'Immediate attention required', score };
}
