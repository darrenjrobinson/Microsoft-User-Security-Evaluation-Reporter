import type { MfaView } from './assessment.js';
import { ok, type Section } from './section.js';

// Authentication strength: what the user has registered, whether that makes them passwordless / phishing-resistant
// capable, and – from beta sign-in authenticationDetails – what they actually use. Registration alone only proves
// capability, so "phishing-resistant" is claimed only when sign-ins show it.

export type MethodKind = 'password' | 'phishingResistant' | 'authenticatorApp' | 'oath' | 'phone' | 'email' | 'tap' | 'other';

export interface AuthMethodView {
  id: string;
  type: string;
  label: string;
  kind: MethodKind;
  detail: string;
  createdDateTime: string | null;
}

export type SignInAuthClass = 'phishingResistant' | 'passwordless' | 'passwordPlusMfa' | 'passwordPlusWeakMfa' | 'singleFactor';

export interface ObservedAuthView {
  /** Interactive sign-ins with authentication evidence (token reuse is excluded) */
  total: number;
  counts: Record<SignInAuthClass, number>;
  /** How often each method appeared in successful authentication steps */
  methods: { method: string; count: number }[];
}

export type AuthStrengthVerdict = 'phishingResistant' | 'passwordlessCapable' | 'phishable' | 'none';

export interface AuthStrengthView {
  verdict: AuthStrengthVerdict;
  summary: string;
  phishingResistantRegistered: boolean;
  passwordlessCapable: boolean;
  /** null when the method inventory couldn't be read */
  methods: AuthMethodView[] | null;
  /** null when sign-in evidence couldn't be read (beta API or licence) */
  observed: ObservedAuthView | null;
}

export interface RecoveryView {
  phoneMethods: number;
  emailMethod: boolean;
  smsSignIn: boolean;
  activeTap: boolean;
  /** Weak recovery / fallback paths, phrased for an operator */
  weakPaths: string[];
}

/* eslint-disable @typescript-eslint/no-explicit-any -- Graph payload shapes are mapped field by field below */
type Any = any;

const METHOD_TYPES: Record<string, { label: string; kind: MethodKind }> = {
  password: { label: 'Password', kind: 'password' },
  fido2: { label: 'Passkey (FIDO2)', kind: 'phishingResistant' },
  windowsHelloForBusiness: { label: 'Windows Hello for Business', kind: 'phishingResistant' },
  platformCredential: { label: 'Platform credential (macOS)', kind: 'phishingResistant' },
  x509Certificate: { label: 'Certificate-based authentication', kind: 'phishingResistant' },
  microsoftAuthenticator: { label: 'Microsoft Authenticator', kind: 'authenticatorApp' },
  softwareOath: { label: 'Authenticator app code (OATH)', kind: 'oath' },
  hardwareOath: { label: 'Hardware OATH token', kind: 'oath' },
  phone: { label: 'Phone', kind: 'phone' },
  email: { label: 'Email', kind: 'email' },
  temporaryAccessPass: { label: 'Temporary Access Pass', kind: 'tap' },
  externalAuthentication: { label: 'External MFA', kind: 'other' },
  qrCodePin: { label: 'QR code + PIN', kind: 'other' },
};

// Registration report values that are phishing-resistant
const PR_REGISTRATION = new Set(['fido2', 'passKeyDeviceBound', 'passKeyDeviceBoundAuthenticator', 'passKeyDeviceBoundWindowsHello', 'windowsHelloForBusiness']);

const str = (v: unknown) => (typeof v === 'string' ? v : '');

export function toAuthMethod(m: Any): AuthMethodView {
  const type = str(m['@odata.type']).replace(/^#microsoft\.graph\./, '').replace(/AuthenticationMethod$/, '');
  const known = METHOD_TYPES[type] ?? { label: type || 'Unknown method', kind: 'other' as const };
  let detail = str(m.displayName);
  if (type === 'phone') detail = [m.phoneType, m.phoneNumber].filter(Boolean).join(' · ');
  if (type === 'email') detail = str(m.emailAddress);
  if (type === 'temporaryAccessPass') detail = m.isUsable ? 'Active – usable now' : 'Expired / used';
  if (type === 'fido2' && m.model && m.model !== m.displayName) detail = [m.displayName, m.model].filter(Boolean).join(' · ');
  return { id: str(m.id), type, label: known.label, kind: known.kind, detail, createdDateTime: m.createdDateTime ?? null };
}

const PR_STEP = /windows hello|fido2|passkey|x\.?509|certificate|platform credential/i;
const PASSWORDLESS_STEP = /passwordless|temporary access pass/i;
const WEAK_STEP = /text message|sms|phone call|voice|email/i;
const IGNORED_STEP = /previously satisfied|satisfied by|token|claim in/i;

/** Buckets one sign-in by its successful authentication steps; null when there's no first-hand evidence. */
export function classifySignIn(details: { authenticationMethod?: string; succeeded?: boolean }[]): SignInAuthClass | null {
  const steps = details.filter((d) => d.succeeded !== false).map((d) => str(d.authenticationMethod)).filter((m) => m && !IGNORED_STEP.test(m));
  if (steps.length === 0) return null;
  if (steps.some((s) => PR_STEP.test(s))) return 'phishingResistant';
  if (steps.some((s) => PASSWORDLESS_STEP.test(s))) return 'passwordless';
  const second = steps.filter((s) => !/^password$/i.test(s));
  if (second.length === 0) return 'singleFactor';
  return second.every((s) => WEAK_STEP.test(s)) ? 'passwordPlusWeakMfa' : 'passwordPlusMfa';
}

export function observeSignIns(signIns: Any[]): ObservedAuthView {
  const counts: Record<SignInAuthClass, number> = { phishingResistant: 0, passwordless: 0, passwordPlusMfa: 0, passwordPlusWeakMfa: 0, singleFactor: 0 };
  const methods = new Map<string, number>();
  let total = 0;
  for (const s of signIns) {
    if ((s.status?.errorCode ?? 0) !== 0 || s.isInteractive === false) continue;
    const details: Any[] = Array.isArray(s.authenticationDetails) ? s.authenticationDetails : [];
    const cls = classifySignIn(details);
    if (!cls) continue;
    total++;
    counts[cls]++;
    for (const d of details) {
      const m = str(d.authenticationMethod);
      if (m && d.succeeded !== false && !IGNORED_STEP.test(m)) methods.set(m, (methods.get(m) ?? 0) + 1);
    }
  }
  return { total, counts, methods: [...methods].map(([method, count]) => ({ method, count })).sort((a, b) => b.count - a.count) };
}

const PATTERNS: [Exclude<SignInAuthClass, 'phishingResistant'>, string][] = [
  ['passwordPlusWeakMfa', 'password + SMS/voice'],
  ['singleFactor', 'password only'],
  ['passwordPlusMfa', 'password + a second factor'],
  ['passwordless', 'a Temporary Access Pass or phone sign-in'],
];

/** The non-phishing-resistant patterns seen, most common first, e.g. "password + SMS/voice and password only". */
function weakObserved(o: ObservedAuthView): string {
  const seen = PATTERNS.filter(([k]) => o.counts[k] > 0).sort(([a], [b]) => o.counts[b] - o.counts[a]).map(([, text]) => text);
  return seen.length > 1 ? `${seen.slice(0, -1).join(', ')} and ${seen.at(-1)}` : (seen[0] ?? '');
}

export function buildAuthStrength(
  mfa: Section<MfaView | null>,
  methods: Section<AuthMethodView[]>,
  observed: Section<ObservedAuthView>,
): Section<AuthStrengthView> {
  const reg = mfa.status === 'ok' ? mfa.data : null;
  const inv = methods.status === 'ok' ? methods.data : null;
  const obs = observed.status === 'ok' ? observed.data : null;
  // An empty sign-in observation proves nothing about what is registered
  if (!reg && !inv && !obs?.total) {
    return mfa.status !== 'ok' ? mfa : methods.status !== 'ok' ? methods : { status: 'unavailable', reason: 'notFound', message: 'No authentication data for this user.' };
  }

  const prRegistered = !!inv?.some((m) => m.kind === 'phishingResistant') || !!reg?.methodsRegistered.some((m) => PR_REGISTRATION.has(m));
  const passwordlessCapable = prRegistered || !!reg?.isPasswordlessCapable;
  // A Temporary Access Pass is onboarding / recovery, not an MFA registration
  const mfaRegistered = !!reg?.isMfaRegistered || !!inv?.some((m) => !['password', 'email', 'tap'].includes(m.kind));
  const prNames = [...new Set((inv ?? []).filter((m) => m.kind === 'phishingResistant').map((m) => m.label))].join(' and ');

  let verdict: AuthStrengthVerdict;
  let summary: string;
  if (obs && obs.total > 0) {
    const weak = obs.counts.singleFactor + obs.counts.passwordPlusWeakMfa;
    const strongShare = obs.counts.phishingResistant / obs.total;
    if (obs.counts.phishingResistant > 0 && weak === 0 && strongShare >= 0.5) {
      verdict = 'phishingResistant';
      summary = `${obs.counts.phishingResistant} of ${obs.total} recent sign-ins used a phishing-resistant method${prNames ? ` (${prNames})` : ''}.`;
    } else if (passwordlessCapable) {
      verdict = 'passwordlessCapable';
      summary = `Registered for passwordless authentication${prNames ? ` with ${prNames}` : ''}, but recent sign-ins still show reliance on ${weakObserved(obs) || 'other methods'}.`;
    } else {
      verdict = mfaRegistered ? 'phishable' : 'none';
      summary = `Recent sign-ins use ${weakObserved(obs) || 'phishable methods'}; no phishing-resistant method is registered.`;
    }
  } else if (passwordlessCapable) {
    verdict = 'passwordlessCapable';
    summary = `Registered for passwordless authentication${prNames ? ` with ${prNames}` : ''}. ${obs ? 'No recent interactive sign-ins to confirm usage.' : 'Sign-in evidence is unavailable, so usage is unconfirmed.'}`;
  } else {
    verdict = mfaRegistered ? 'phishable' : 'none';
    summary = mfaRegistered ? 'Registered for MFA with phishable methods only.' : 'No multifactor or passwordless method is registered.';
  }

  return ok({ verdict, summary, phishingResistantRegistered: prRegistered, passwordlessCapable, methods: inv, observed: obs });
}

export function buildRecovery(methods: Section<AuthMethodView[]>, raw: Any[]): Section<RecoveryView> {
  if (methods.status !== 'ok') return methods;
  const phones = raw.filter((m) => str(m['@odata.type']).endsWith('phoneAuthenticationMethod'));
  const smsSignIn = phones.some((p) => p.smsSignInState === 'ready');
  const emailMethod = methods.data.some((m) => m.kind === 'email');
  const activeTap = raw.some((m) => str(m['@odata.type']).endsWith('temporaryAccessPassAuthenticationMethod') && m.isUsable);

  const weakPaths: string[] = [];
  if (phones.length > 1) weakPaths.push(`${phones.length} phone numbers registered (SMS/voice)`);
  else if (phones.length === 1) weakPaths.push('Phone (SMS/voice) registered');
  if (smsSignIn) weakPaths.push('SMS sign-in enabled');
  if (emailMethod) weakPaths.push('Email one-time passcode registered');
  if (activeTap) weakPaths.push('Temporary Access Pass is active');
  return ok({ phoneMethods: phones.length, emailMethod, smsSignIn, activeTap, weakPaths });
}
