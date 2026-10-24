import type { GraphRequest } from './client.js';

// Every Graph call the app makes is defined here. Callers supply only validated values
// (object ids, search text) – never URLs – so the API can't be used as a generic Graph proxy.

export const ACTIVITY_WINDOW_DAYS = 30;

const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isObjectId(value: string): boolean {
  return GUID.test(value);
}

function assertObjectId(id: string): string {
  if (!isObjectId(id)) throw new Error(`Invalid object id: ${id}`);
  return id.toLowerCase();
}

/** OData string literal escaping: a single quote is doubled. */
export function odataString(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

/** Strips characters that would break out of a $search="property:value" clause. */
export function sanitizeSearch(value: string): string {
  return value.replace(/["\\:]/g, ' ').replace(/\s+/g, ' ').trim();
}

/** Graph wants `2024-01-01T00:00:00Z` (no millis) in audit/sign-in filters. */
export function isoNoMillis(date: Date): string {
  return date.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function q(params: Record<string, string>): string {
  return Object.entries(params)
    .map(([k, v]) => `${k}=${encodeURIComponent(v)}`)
    .join('&');
}

const USER_SELECT = [
  'id',
  'displayName',
  'givenName',
  'surname',
  'jobTitle',
  'mail',
  'mobilePhone',
  'officeLocation',
  'userType',
  'department',
  'city',
  'userPrincipalName',
  'accountEnabled',
  'createdDateTime',
  'lastPasswordChangeDateTime',
  'onPremisesSyncEnabled',
  'onPremisesSecurityIdentifier',
  'onPremisesDistinguishedName',
  'onPremisesSamAccountName',
  'assignedPlans',
].join(',');

const SEARCH_SELECT = 'id,displayName,userPrincipalName,mail,department,jobTitle,userType,onPremisesSyncEnabled,accountEnabled';

const DEVICE_SELECT =
  'id,displayName,operatingSystem,operatingSystemVersion,trustType,isCompliant,isManaged,approximateLastSignInDateTime';

export const queries = {
  secureScore: (): string => `/security/secureScores?${q({ $top: '1' })}`,

  recentRiskDetections: (now = new Date()): string => {
    const since = new Date(now.getTime() - ACTIVITY_WINDOW_DAYS * 86_400_000);
    return `/identityProtection/riskDetections?${q({
      $filter: `riskState eq 'atRisk' and detectedDateTime ge ${isoNoMillis(since)}`,
      $top: '100',
    })}`;
  },

  searchUsers: (text: string): { url: string; headers: Record<string, string> } => {
    const term = sanitizeSearch(text);
    return {
      url: `/users?${q({
        $search: `"displayName:${term}" OR "userPrincipalName:${term}" OR "mail:${term}"`,
        $select: SEARCH_SELECT,
        $orderby: 'displayName',
        $count: 'true',
        $top: '25',
      })}`,
      headers: { ConsistencyLevel: 'eventual' },
    };
  },

  /** The per-user lookups, sent together as one JSON batch (as the original MSUser-Batch function did). */
  userProfileBatch: (userId: string, now = new Date()): GraphRequest[] => {
    const id = assertObjectId(userId);
    const since = isoNoMillis(new Date(now.getTime() - ACTIVITY_WINDOW_DAYS * 86_400_000));
    return [
      {
        id: 'user',
        method: 'GET',
        url: `/users/${id}?${q({ $select: USER_SELECT, $expand: 'manager($select=displayName,userPrincipalName)' })}`,
      },
      {
        id: 'devices',
        method: 'GET',
        url: `/users/${id}/registeredDevices/microsoft.graph.device?${q({ $select: DEVICE_SELECT })}`,
      },
      {
        id: 'signIns',
        method: 'GET',
        url: `/auditLogs/signIns?${q({ $filter: `userId eq '${id}' and createdDateTime ge ${since}`, $top: '10' })}`,
      },
      {
        id: 'sspr',
        method: 'GET',
        url: `/auditLogs/directoryAudits?${q({
          $filter: `loggedByService eq 'Self-service Password Management' and targetResources/any(t:t/id eq '${id}') and activityDateTime ge ${since}`,
          $top: '50',
        })}`,
      },
      {
        id: 'riskDetections',
        method: 'GET',
        url: `/identityProtection/riskDetections?${q({ $filter: `userId eq '${id}'`, $top: '50' })}`,
      },
      { id: 'riskyUser', method: 'GET', url: `/identityProtection/riskyUsers/${id}` },
      { id: 'mfa', method: 'GET', url: `/reports/authenticationMethods/userRegistrationDetails/${id}` },
      { id: 'authMethods', method: 'GET', url: `/users/${id}/authentication/methods` },
      // Active roles with PIM schedule detail (P2), the plain assignment list as a no-P2 fallback, then eligibilities
      {
        id: 'roleSchedules',
        method: 'GET',
        url: `/roleManagement/directory/roleAssignmentScheduleInstances?${q({ $filter: `principalId eq '${id}'`, $expand: 'roleDefinition' })}`,
      },
      {
        id: 'roleAssignments',
        method: 'GET',
        url: `/roleManagement/directory/roleAssignments?${q({ $filter: `principalId eq '${id}'`, $expand: 'roleDefinition' })}`,
      },
      {
        id: 'roleEligibilities',
        method: 'GET',
        url: `/roleManagement/directory/roleEligibilityScheduleInstances?${q({ $filter: `principalId eq '${id}'`, $expand: 'roleDefinition' })}`,
      },
      { id: 'ownedObjects', method: 'GET', url: `/users/${id}/ownedObjects?${q({ $top: '100' })}` },
      { id: 'sponsorOf', method: 'GET', url: `/users/${id}/sponsorOf?${q({ $top: '100' })}` },
      { id: 'memberOf', method: 'GET', url: `/users/${id}/memberOf?${q({ $top: '999' })}` },
      {
        id: 'transitiveGroups',
        method: 'GET',
        url: `/users/${id}/transitiveMemberOf/microsoft.graph.group?${q({ $count: 'true', $top: '1', $select: 'id' })}`,
        headers: { ConsistencyLevel: 'eventual' },
      },
      {
        id: 'methodAudits',
        method: 'GET',
        url: `/auditLogs/directoryAudits?${q({
          $filter: `loggedByService eq 'Authentication Methods' and targetResources/any(t:t/id eq '${id}') and activityDateTime ge ${since}`,
          $top: '50',
        })}`,
      },
      {
        id: 'guestInvites',
        method: 'GET',
        url: `/auditLogs/directoryAudits?${q({
          $filter: `activityDisplayName eq 'Invite external user' and initiatedBy/user/id eq '${id}' and activityDateTime ge ${since}`,
          $top: '100',
        })}`,
      },
    ];
  },

  /**
   * Role assignments held by role-assignable groups the user belongs to. Directory roles granted through a group
   * name the group, not the member, as principal. (Role-assignable groups can't contain other groups.)
   */
  groupRoleBatch: (groupIds: string[]): GraphRequest[] =>
    groupIds.flatMap((groupId) => {
      const id = assertObjectId(groupId);
      const filter = `principalId eq '${id}'`;
      return [
        { id: `${id}:roleSchedules`, method: 'GET' as const, url: `/roleManagement/directory/roleAssignmentScheduleInstances?${q({ $filter: filter, $expand: 'roleDefinition' })}` },
        { id: `${id}:roleAssignments`, method: 'GET' as const, url: `/roleManagement/directory/roleAssignments?${q({ $filter: filter, $expand: 'roleDefinition' })}` },
        { id: `${id}:roleEligibilities`, method: 'GET' as const, url: `/roleManagement/directory/roleEligibilityScheduleInstances?${q({ $filter: filter, $expand: 'roleDefinition' })}` },
      ];
    }),

  /** Sign-ins with authenticationDetails (beta only) – the evidence for which methods are actually used. */
  userAuthSignInsBeta: (userId: string, now = new Date()): GraphRequest[] => {
    const id = assertObjectId(userId);
    const since = isoNoMillis(new Date(now.getTime() - ACTIVITY_WINDOW_DAYS * 86_400_000));
    return [
      {
        id: 'authSignIns',
        method: 'GET',
        url: `/auditLogs/signIns?${q({ $filter: `userId eq '${id}' and createdDateTime ge ${since}`, $top: '50' })}`,
      },
    ];
  },

  /** Tenant-wide settings that explain a user's posture (cached by the caller). */
  tenantPolicies: (): GraphRequest[] => [
    { id: 'authMethodsPolicy', method: 'GET', url: '/policies/authenticationMethodsPolicy' },
    { id: 'securityDefaults', method: 'GET', url: '/policies/identitySecurityDefaultsEnforcementPolicy' },
  ],
};
