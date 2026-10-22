import type { GraphClient, GraphResponse } from '../graph/client.js';
import { queries } from '../graph/queries.js';
import {
  assessDevices,
  assessMfa,
  assessPassword,
  assessRisk,
  assessSspr,
  overallOf,
  type Assessment,
  type MfaView,
  type RiskyUserView,
} from './assessment.js';
import type { HibpLookup, HibpView } from './hibp.js';
import { byNewest, toRiskView, type GraphRiskDetection, type RiskDetectionView } from './risk.js';
import { isOk, ok, unavailableFrom, valueOf, type Section } from './section.js';
import { accountTypeOf, type AccountType } from './users.js';

export interface UserDetailsView {
  id: string;
  displayName: string;
  userPrincipalName: string;
  mail: string;
  jobTitle: string;
  department: string;
  officeLocation: string;
  city: string;
  mobilePhone: string;
  accountEnabled: boolean;
  accountType: AccountType;
  manager: string;
  createdDateTime: string | null;
  lastPasswordChangeDateTime: string | null;
  onPremisesSamAccountName: string;
  onPremisesDistinguishedName: string;
  onPremisesSecurityIdentifier: string;
}

export interface DeviceView {
  displayName: string;
  operatingSystem: string;
  trustType: string;
  joinType: string;
  isCompliant: boolean | null;
  isManaged: boolean | null;
  lastSignIn: string | null;
}

export interface SignInView {
  createdDateTime: string;
  appDisplayName: string;
  ipAddress: string;
  location: string;
  clientAppUsed: string;
  operatingSystem: string;
  browser: string;
  deviceTrustType: string;
  succeeded: boolean;
  failureReason: string;
  conditionalAccessStatus: string;
  authenticationRequirement: string;
  riskLevel: string;
}

export interface SsprEventView {
  activityDateTime: string;
  activity: string;
  result: string;
  resultReason: string;
}

export interface UserProfile {
  user: UserDetailsView;
  assessment: Assessment;
  riskDetections: Section<RiskDetectionView[]>;
  riskyUser: Section<RiskyUserView | null>;
  mfa: Section<MfaView | null>;
  hibp: Section<HibpView>;
  signIns: Section<SignInView[]>;
  sspr: Section<SsprEventView[]>;
  devices: Section<DeviceView[]>;
}

/* eslint-disable @typescript-eslint/no-explicit-any -- Graph payload shapes are mapped field by field below */
type Any = any;

const JOIN_TYPES: Record<string, string> = {
  AzureAd: 'Microsoft Entra joined',
  ServerAd: 'Microsoft Entra hybrid joined',
  Workplace: 'Microsoft Entra registered',
};

const str = (v: unknown) => (typeof v === 'string' ? v : '');

function toUser(u: Any): UserDetailsView {
  return {
    id: u.id,
    displayName: str(u.displayName),
    userPrincipalName: str(u.userPrincipalName),
    mail: str(u.mail),
    jobTitle: str(u.jobTitle),
    department: str(u.department),
    officeLocation: str(u.officeLocation),
    city: str(u.city),
    mobilePhone: str(u.mobilePhone),
    accountEnabled: u.accountEnabled ?? true,
    accountType: accountTypeOf(u),
    manager: str(u.manager?.displayName),
    createdDateTime: u.createdDateTime ?? null,
    lastPasswordChangeDateTime: u.lastPasswordChangeDateTime ?? null,
    onPremisesSamAccountName: str(u.onPremisesSamAccountName),
    onPremisesDistinguishedName: str(u.onPremisesDistinguishedName),
    onPremisesSecurityIdentifier: str(u.onPremisesSecurityIdentifier),
  };
}

function toDevice(d: Any): DeviceView {
  return {
    displayName: str(d.displayName),
    operatingSystem: [d.operatingSystem, d.operatingSystemVersion].filter(Boolean).join(' '),
    trustType: str(d.trustType),
    joinType: JOIN_TYPES[d.trustType] ?? (d.trustType || 'Unknown'),
    isCompliant: d.isCompliant ?? null,
    isManaged: d.isManaged ?? null,
    lastSignIn: d.approximateLastSignInDateTime ?? null,
  };
}

function toSignIn(s: Any): SignInView {
  const loc = s.location ?? {};
  return {
    createdDateTime: s.createdDateTime,
    appDisplayName: str(s.appDisplayName),
    ipAddress: str(s.ipAddress),
    location: [loc.city, loc.state, loc.countryOrRegion].filter(Boolean).join(', '),
    clientAppUsed: str(s.clientAppUsed),
    operatingSystem: str(s.deviceDetail?.operatingSystem),
    browser: str(s.deviceDetail?.browser),
    deviceTrustType: str(s.deviceDetail?.trustType),
    succeeded: (s.status?.errorCode ?? 0) === 0,
    failureReason: s.status?.errorCode ? str(s.status?.failureReason) : '',
    conditionalAccessStatus: str(s.conditionalAccessStatus),
    authenticationRequirement: str(s.authenticationRequirement),
    riskLevel: str(s.riskLevelDuringSignIn),
  };
}

function toSspr(a: Any): SsprEventView {
  return {
    activityDateTime: a.activityDateTime,
    activity: str(a.activityDisplayName),
    result: str(a.result),
    resultReason: str(a.resultReason),
  };
}

function toMfa(m: Any): MfaView {
  return {
    isMfaRegistered: !!m.isMfaRegistered,
    isMfaCapable: !!m.isMfaCapable,
    isPasswordlessCapable: !!m.isPasswordlessCapable,
    isSsprRegistered: !!m.isSsprRegistered,
    defaultMfaMethod: str(m.defaultMfaMethod),
    userPreferredMethod: str(m.userPreferredMethodForSecondaryAuthentication),
    methodsRegistered: Array.isArray(m.methodsRegistered) ? m.methodsRegistered : [],
    systemPreferredMethods: Array.isArray(m.systemPreferredAuthenticationMethods)
      ? m.systemPreferredAuthenticationMethods
      : [],
    lastUpdatedDateTime: m.lastUpdatedDateTime ?? null,
  };
}

function section<T>(res: GraphResponse | undefined, map: (res: GraphResponse) => T): Section<T> {
  return res && isOk(res) ? ok(map(res)) : unavailableFrom(res);
}

export class UserNotFoundError extends Error {}

export function createProfileService(graph: GraphClient, hibp: HibpLookup) {
  return async function getUserProfile(userId: string): Promise<UserProfile> {
    const responses = await graph.batch(queries.userProfileBatch(userId));
    const userRes = responses.get('user');
    if (!userRes || !isOk(userRes)) {
      if (userRes?.status === 404) throw new UserNotFoundError(userId);
      const why = unavailableFrom(userRes);
      throw new Error(`Could not read user: ${why.message}`);
    }
    const user = toUser(userRes.body);

    const riskDetections = section(responses.get('riskDetections'), (r) =>
      valueOf<GraphRiskDetection>(r).sort(byNewest).map(toRiskView),
    );
    const riskyRes = responses.get('riskyUser');
    // Not being in riskyUsers just means the user has never been flagged
    const riskyUser: Section<RiskyUserView | null> =
      riskyRes?.status === 404
        ? ok(null)
        : section(riskyRes, (r) => {
            const b = r.body as Any;
            return { riskLevel: str(b.riskLevel), riskState: str(b.riskState), riskLastUpdatedDateTime: b.riskLastUpdatedDateTime ?? null };
          });
    const mfaRes = responses.get('mfa');
    const mfa: Section<MfaView | null> = mfaRes?.status === 404 ? ok(null) : section(mfaRes, (r) => toMfa(r.body));
    const signIns = section(responses.get('signIns'), (r) => valueOf(r).map(toSignIn));
    const sspr = section(responses.get('sspr'), (r) =>
      valueOf<Any>(r)
        .map(toSspr)
        .sort((a, b) => b.activityDateTime.localeCompare(a.activityDateTime)),
    );
    const devices = section(responses.get('devices'), (r) => valueOf(r).map(toDevice));

    const account = user.mail || user.userPrincipalName;
    const hibpResult = await hibp(account).catch(
      (): Section<HibpView> => ({ status: 'unavailable', reason: 'error', message: 'Have I Been Pwned lookup failed.' }),
    );

    const checks = {
      risk: assessRisk(riskDetections, riskyUser),
      password: assessPassword(hibpResult, riskDetections),
      mfa: assessMfa(mfa, user.accountType),
      devices: assessDevices(devices),
      sspr: assessSspr(sspr),
    };

    return {
      user,
      assessment: { ...checks, overall: overallOf(checks) },
      riskDetections,
      riskyUser,
      mfa,
      hibp: hibpResult,
      signIns,
      sspr,
      devices,
    };
  };
}
