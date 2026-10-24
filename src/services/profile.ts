import type { GraphClient, GraphResponse } from '../graph/client.js';
import { allPages } from '../graph/paging.js';
import { queries } from '../graph/queries.js';
import type { Policy } from '../policy.js';
import {
  assessAdminHygiene,
  assessAuthStrength,
  assessCaPosture,
  assessCredentialChanges,
  assessDevices,
  assessGuestGovernance,
  assessMembership,
  assessMfaRegistration,
  assessOwnership,
  assessPassword,
  assessPimDrift,
  assessPrivilege,
  assessRecovery,
  assessRisk,
  assessSspr,
  overallOf,
  withCredentialSignal,
  type Assessment,
  type MfaView,
  type RiskyUserView,
} from './assessment.js';
import {
  buildAuthStrength,
  buildRecovery,
  observeSignIns,
  toAuthMethod,
  type AuthStrengthView,
  type ObservedAuthView,
  type RecoveryView,
} from './authStrength.js';
import { buildCaPosture, type CaPostureView } from './caPosture.js';
import { buildCredentialChanges, type CredentialChangesView } from './credentialChanges.js';
import type { HibpLookup, HibpView } from './hibp.js';
import { buildIdentity, type IdentityView } from './identity.js';
import { toLicence, type LicenceView } from './licences.js';
import { buildPrivilege, isPrivileged, type GroupRoleResponses, type PrivilegeView } from './privilege.js';
import {
  buildGuests,
  buildMembership,
  buildOwnership,
  inBreakGlassGroup,
  type GuestGovernanceView,
  type MembershipView,
  type OwnershipView,
} from './relationships.js';
import { byNewest, toRiskView, type GraphRiskDetection, type RiskDetectionView } from './risk.js';
import { isOk, ok, unavailableFrom, valueOf, type Section } from './section.js';
import { createTenantContext, type TenantContextView } from './tenantContext.js';
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
  managerJobTitle: string;
  managerUpn: string;
  companyName: string;
  employeeType: string;
  employeeId: string;
  employeeHireDate: string | null;
  state: string;
  country: string;
  usageLocation: string;
  businessPhones: string[];
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
  id: string;
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
  /** Methods used, from beta authenticationDetails; empty when that evidence is unavailable */
  authMethods: string[];
}

export interface SsprEventView {
  activityDateTime: string;
  activity: string;
  result: string;
  resultReason: string;
}

/** Who this person is in the organisation – context for reading the security findings */
export interface UserContextView {
  signInActivity: Section<{ lastSignIn: string | null; lastNonInteractiveSignIn: string | null; lastSuccessfulSignIn: string | null }>;
  licences: Section<LicenceView[]>;
  directReports: Section<number>;
}

export interface UserProfile {
  user: UserDetailsView;
  context: UserContextView;
  identity: IdentityView;
  assessment: Assessment;
  riskDetections: Section<RiskDetectionView[]>;
  riskyUser: Section<RiskyUserView | null>;
  mfa: Section<MfaView | null>;
  authStrength: Section<AuthStrengthView>;
  recovery: Section<RecoveryView>;
  privilege: Section<PrivilegeView>;
  ownership: Section<OwnershipView>;
  guests: Section<GuestGovernanceView>;
  membership: Section<MembershipView>;
  credentialChanges: Section<CredentialChangesView>;
  caPosture: Section<CaPostureView>;
  hibp: Section<HibpView>;
  signIns: Section<SignInView[]>;
  sspr: Section<SsprEventView[]>;
  devices: Section<DeviceView[]>;
  /** Tenant settings and licence gaps that explain this user's findings */
  tenant: { context: Section<TenantContextView>; notes: string[] };
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
    managerJobTitle: str(u.manager?.jobTitle),
    managerUpn: str(u.manager?.userPrincipalName),
    companyName: str(u.companyName),
    employeeType: str(u.employeeType),
    employeeId: str(u.employeeId),
    employeeHireDate: u.employeeHireDate ?? null,
    state: str(u.state),
    country: str(u.country),
    usageLocation: str(u.usageLocation),
    businessPhones: Array.isArray(u.businessPhones) ? u.businessPhones.filter((x: unknown) => typeof x === 'string') : [],
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

function toSignIn(s: Any, authMethods: string[] = []): SignInView {
  const loc = s.location ?? {};
  return {
    id: str(s.id),
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
    authMethods,
  };
}

const stepMethods = (s: Any): string[] =>
  Array.isArray(s.authenticationDetails)
    ? [...new Set<string>(s.authenticationDetails.filter((d: Any) => d.succeeded !== false).map((d: Any) => str(d.authenticationMethod)).filter(Boolean))]
    : [];

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

function tenantNotes(
  context: Section<TenantContextView>,
  sections: { authStrength: Section<AuthStrengthView>; privilege: Section<PrivilegeView>; risk: Section<unknown>; observed: Section<unknown> },
): string[] {
  const notes: string[] = [];
  if (context.status === 'ok') {
    const c = context.data;
    if (c.methodsDisabled.includes('Passkeys (FIDO2)')) notes.push("Passkeys (FIDO2) are disabled in the authentication methods policy, so users can't register a phishing-resistant credential.");
    const weak = c.methodsEnabled.filter((m) => m === 'SMS' || m === 'Voice call' || m === 'Email OTP');
    const reliesOnWeak = sections.authStrength.status === 'ok' && ['phishable', 'none'].includes(sections.authStrength.data.verdict);
    if (weak.length && reliesOnWeak) notes.push(`${weak.join(', ')} ${weak.length === 1 ? 'is' : 'are'} enabled tenant-wide as authentication methods.`);
    if (c.securityDefaults) notes.push('Security defaults are on: Conditional Access and PIM controls are not in use.');
  }
  if (sections.privilege.status === 'ok' && !sections.privilege.data.pimDetail) {
    notes.push('PIM schedules need Microsoft Entra ID P2 – role assignments are shown without eligibility or expiry.');
  }
  if (sections.risk.status === 'unavailable' && sections.risk.reason === 'notLicensed') notes.push('Risk detections need Microsoft Entra ID P2.');
  if (sections.observed.status === 'unavailable') notes.push("Sign-in authentication details (Graph beta) are unavailable, so actual method usage can't be confirmed.");
  return notes;
}

// Each group costs three lookups; six keeps the follow-up inside one 20-request batch
const MAX_ROLE_GROUPS = 6;
// Inventories that can run past one page
const PAGED = ['ownedObjects', 'sponsorOf', 'memberOf', 'guestInvites', 'methodAudits'] as const;

/** Roles held through the role-assignable groups the user is a direct member of (they can't be nested). */
async function groupRoles(graph: GraphClient, memberOf: { res: GraphResponse | undefined; complete: boolean }): Promise<{ results: GroupRoleResponses[]; gaps: string[] }> {
  const gaps: string[] = [];
  if (!isOk(memberOf.res)) return { results: [], gaps: ["Roles held through role-assignable groups couldn't be checked: group memberships are unavailable."] };
  if (!memberOf.complete) gaps.push('Group memberships were truncated, so roles held through some groups may be missing.');
  const groups = valueOf<Any>(memberOf.res!).filter((o) => o['@odata.type'] === '#microsoft.graph.group' && o.isAssignableToRole);
  const checked = groups.slice(0, MAX_ROLE_GROUPS);
  if (groups.length > checked.length) gaps.push(`Only ${checked.length} of ${groups.length} role-assignable groups were checked for roles.`);
  if (checked.length === 0) return { results: [], gaps };
  const responses = await graph.batch(queries.groupRoleBatch(checked.map((g) => String(g.id)))).catch(() => null);
  if (!responses) return { results: [], gaps: [...gaps, "Roles held through role-assignable groups couldn't be read."] };
  const results = checked.map((g) => {
    const id = String(g.id).toLowerCase();
    return {
      groupName: str(g.displayName) || id,
      schedules: responses.get(`${id}:roleSchedules`),
      assignments: responses.get(`${id}:roleAssignments`),
      eligibilities: responses.get(`${id}:roleEligibilities`),
    };
  });
  return { results, gaps };
}

export function createProfileService(graph: GraphClient, hibp: HibpLookup, policy: Policy) {
  const getTenantContext = createTenantContext(graph);

  return async function getUserProfile(userId: string): Promise<UserProfile> {
    const batch = queries.userProfileBatch(userId);
    const [responses, beta, tenantContext] = await Promise.all([
      graph.batch(batch),
      // beta is the only source of per-sign-in authentication methods; failure just leaves usage unconfirmed
      graph.batch(queries.userAuthSignInsBeta(userId), { version: 'beta' }).catch(() => new Map<string, GraphResponse>()),
      getTenantContext().catch((): Section<TenantContextView> => ({ status: 'unavailable', reason: 'error', message: 'Tenant policies could not be read.' })),
    ]);
    const userRes = responses.get('user');
    if (!userRes || !isOk(userRes)) {
      if (userRes?.status === 404) throw new UserNotFoundError(userId);
      const why = unavailableFrom(userRes);
      throw new Error(`Could not read user: ${why.message}`);
    }
    const rawUser = userRes.body as Any;
    const user = toUser(rawUser);

    const [owned, sponsorOf, memberOf, guestInvites, methodAudits] = await Promise.all(
      PAGED.map((id) => allPages(graph, batch.find((r) => r.id === id)!, responses.get(id))),
    );
    const account = user.mail || user.userPrincipalName;
    const [roleGroups, hibpResult] = await Promise.all([
      groupRoles(graph, memberOf!),
      hibp(account).catch((): Section<HibpView> => ({ status: 'unavailable', reason: 'error', message: 'Have I Been Pwned lookup failed.' })),
    ]);

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

    // Sign-ins: the v1.0 panel query, enriched with beta authentication details where available
    const betaRes = beta.get('authSignIns');
    const betaSignIns: Any[] | null = isOk(betaRes) ? valueOf<Any>(betaRes!) : null;
    const betaById = new Map((betaSignIns ?? []).map((s) => [str(s.id), s]));
    const v1SignIns: Any[] | null = isOk(responses.get('signIns')) ? valueOf<Any>(responses.get('signIns')!) : null;
    const signIns = section(responses.get('signIns'), (r) => valueOf<Any>(r).map((s) => toSignIn(s, stepMethods(betaById.get(str(s.id)) ?? {}))));
    const observed: Section<ObservedAuthView> = betaSignIns ? ok(observeSignIns(betaSignIns)) : unavailableFrom(betaRes);

    const sspr = section(responses.get('sspr'), (r) =>
      valueOf<Any>(r)
        .map(toSspr)
        .sort((a, b) => b.activityDateTime.localeCompare(a.activityDateTime)),
    );
    const devices = section(responses.get('devices'), (r) => valueOf(r).map(toDevice));

    const methodsRes = responses.get('authMethods');
    const rawMethods: Any[] = isOk(methodsRes) ? valueOf<Any>(methodsRes!) : [];
    const authMethods = section(methodsRes, () => rawMethods.map(toAuthMethod));
    const authStrength = buildAuthStrength(mfa, authMethods, observed);
    const recovery = buildRecovery(authMethods, rawMethods);

    const privilege = buildPrivilege(
      { schedules: responses.get('roleSchedules'), assignments: responses.get('roleAssignments'), eligibilities: responses.get('roleEligibilities') },
      user.id,
      policy,
      roleGroups,
    );
    const ownership = buildOwnership(owned!, policy);
    const guests = buildGuests(sponsorOf!, guestInvites!);
    const membership = buildMembership(memberOf!, responses.get('transitiveGroups'), policy);
    const credentialChanges = buildCredentialChanges(
      section(methodAudits!.res, (r) => valueOf<Any>(r)),
      authMethods,
      riskDetections,
      (betaSignIns ?? v1SignIns ?? []).map((s) => ({ createdDateTime: str(s.createdDateTime), riskLevel: str(s.riskLevelDuringSignIn) })),
      user.id,
    );
    const caSource = betaSignIns ?? v1SignIns;
    const caPosture: Section<CaPostureView> = caSource
      ? ok(buildCaPosture(caSource, betaSignIns ? 'beta' : 'v1.0'))
      : unavailableFrom(responses.get('signIns'));

    const identity = buildIdentity({ ...user, raw: rawUser }, policy, {
      // Owning a role-assignable group means being able to add yourself to its roles
      isPrivileged: isPrivileged(privilege) || (ownership.status === 'ok' && (ownership.data.counts.roleAssignableGroup ?? 0) > 0),
      inBreakGlassGroup: inBreakGlassGroup(memberOf!.res, policy),
    });

    const credentialCheck = assessCredentialChanges(credentialChanges, identity);
    const weighted = {
      mfa: assessMfaRegistration(mfa, identity),
      authStrength: assessAuthStrength(authStrength, identity),
      risk: withCredentialSignal(assessRisk(riskDetections, riskyUser), credentialCheck),
      password: assessPassword(hibpResult, riskDetections),
      privilege: assessPrivilege(privilege, identity),
      guests: assessGuestGovernance(guests, identity, policy),
      membership: assessMembership(membership, identity, policy),
    };
    const overlays = {
      pimDrift: assessPimDrift(privilege),
      ownership: assessOwnership(ownership),
      recovery: assessRecovery(recovery, authStrength),
      credentialChanges: credentialCheck,
      adminHygiene: assessAdminHygiene(identity, authStrength, privilege, recovery),
      caPosture: assessCaPosture(caPosture.status === 'ok' ? caPosture.data : null, identity),
      devices: assessDevices(devices),
      sspr: assessSspr(sspr),
    };

    const context: UserContextView = {
      signInActivity: section(responses.get('signInActivity'), (r) => {
        const a = (r.body as Any).signInActivity ?? {};
        return {
          lastSignIn: a.lastSignInDateTime ?? null,
          lastNonInteractiveSignIn: a.lastNonInteractiveSignInDateTime ?? null,
          lastSuccessfulSignIn: a.lastSuccessfulSignInDateTime ?? null,
        };
      }),
      licences: section(responses.get('licenses'), (r) => valueOf<Any>(r).map(toLicence).sort((a, b) => a.name.localeCompare(b.name))),
      directReports: section(responses.get('directReports'), (r) => Number((r.body as Any)['@odata.count'] ?? valueOf(r).length) || 0),
    };

    return {
      user,
      context,
      identity,
      assessment: { ...weighted, ...overlays, overall: overallOf(weighted) },
      riskDetections,
      riskyUser,
      mfa,
      authStrength,
      recovery,
      privilege,
      ownership,
      guests,
      membership,
      credentialChanges,
      caPosture,
      hibp: hibpResult,
      signIns,
      sspr,
      devices,
      tenant: { context: tenantContext, notes: tenantNotes(tenantContext, { authStrength, privilege, risk: riskDetections, observed }) },
    };
  };
}
