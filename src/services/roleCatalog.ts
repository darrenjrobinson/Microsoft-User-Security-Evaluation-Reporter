import atlas from '../data/graph-atlas-roles.json' with { type: 'json' };

// Role criticality enrichment. Raw role data (name, template id, Microsoft's "privileged" label and the
// microsoft.directory/* actions) is a snapshot from Graph-atlas – refresh it with `npm run sync:atlas`.
// Graph-atlas has no blast-radius or tier data, so impact and themes are derived here from the actions.

export type Impact = 'high' | 'medium' | 'low';

export interface RoleClassification {
  templateId: string;
  name: string;
  /** Microsoft's "privileged" label – also set on some read-only roles such as Global Reader */
  isPrivileged: boolean;
  impact: Impact;
  themes: string[];
  pimRecommended: boolean;
  /** False for custom roles and anything missing from the snapshot */
  known: boolean;
}

interface AtlasRole {
  templateId: string;
  name: string;
  isPrivileged: boolean;
  actions: string[];
}

export const atlasSource = atlas.source;

// Action patterns that put the tenant or other identities within reach. The first group alone makes a role high impact.
const HIGH_THEMES: [string, RegExp][] = [
  ['Privilege escalation', /\/(roleAssignments|roleDefinitions|privilegedIdentityManagement)\/.*(allTasks|update|create|delete)$|\/appRoleAssignedTo\/update$/],
  ['Credential reset', /\/users\/(password|authenticationMethods)\/.*(update|create|delete|allTasks)$|\/users\/password\/update$/],
  ['Access policy', /\/(conditionalAccessPolicies|authorizationPolicy|crossTenantAccessPolicy|authenticationMethodsPolicy)\/.*(allTasks|update|create|delete)$/],
  ['App credential takeover', /\/(applications|servicePrincipals|agentIdentityBlueprints)\/credentials\/update$|\/servicePrincipals\/.*[cC]redentials\/manage$/],
  ['Federation / tenant takeover', /\/domains\/(allProperties\/allTasks|federationConfiguration\/.*(update|create|delete))$/],
];
const MEDIUM_THEMES: [string, RegExp][] = [
  // BitLocker / LAPS secrets – held by several reader roles, so notable but not high impact on its own
  ['Secret read', /\/(deviceLocalCredentials\/password\/read|bitlockerKeys\/key\/read)$|\/getPasswordSingleSignOnCredentials$/],
  ['Workload admin', /^microsoft\.(intune|office365\.(exchange|sharePoint|securityComplianceCenter)|windows\.defenderAdvancedThreatProtection)\/allEntities\/(basic\/)?allTasks$/],
  ['Directory write', /^microsoft\.directory\/(users|groups|devices)\/.*(allTasks|update|create|delete)$/],
];
const READ_ONLY = /\/(read|restrictedRead)$|\/allProperties\/read$/;
// Tenant-wide service health / support tickets are granted to most admin roles and say nothing about blast radius
const NOISE = /\.(serviceHealth|supportTickets)\//;

// The roles the PRD calls out by name are always high impact, whatever the action heuristics say
const ALWAYS_HIGH = new Set([
  '62e90394-69f5-4237-9190-012177145e10', // Global Administrator
  'e8611ab8-c189-46e8-94e1-60213ab1f814', // Privileged Role Administrator
  'c4e39bd9-1100-46d3-8c65-fb160da0071f', // Authentication Administrator
  '7be44c8a-adaf-4e2a-84d6-ab2649e08a13', // Privileged Authentication Administrator
  'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9', // Conditional Access Administrator
  '194ae4cb-b126-40b2-bd5b-6091b380977d', // Security Administrator
  '5f2222b1-57c3-48ba-8ad5-d4759f1fde6f', // Security Operator
  '29232cdf-9323-42fd-ade2-1d097af3e4de', // Exchange Administrator
  'f28a1f50-f6e7-4571-818b-6a12f2af6b6c', // SharePoint Administrator
  '3a2c62db-5318-420d-8d74-23affee5d9d5', // Intune Administrator
  'fe930be7-5e62-47db-91af-98c3a49a38b1', // User Administrator
]);

// Roles whose power isn't expressed as directory actions
const AT_LEAST_MEDIUM: Record<string, string> = {
  '9f06204d-73c1-4d4c-880a-6edb90606fd8': 'Local admin on every Entra joined device', // Entra Joined Device Local Administrator
};

export function classify(role: AtlasRole): RoleClassification {
  const actions = role.actions.filter((a) => !NOISE.test(a));
  const match = (themes: [string, RegExp][]) => themes.filter(([, re]) => actions.some((a) => re.test(a))).map(([t]) => t);
  const high = match(HIGH_THEMES);
  const medium = match(MEDIUM_THEMES);
  const extra = AT_LEAST_MEDIUM[role.templateId];
  if (extra) medium.push(extra);
  const writes = actions.some((a) => !READ_ONLY.test(a));

  let impact: Impact = high.length > 0 ? 'high' : medium.length > 0 || writes ? 'medium' : 'low';
  // Privileged readers (Global Reader, Security Reader…) see enough to plan an attack
  if (impact === 'low' && role.isPrivileged) impact = 'medium';
  if (ALWAYS_HIGH.has(role.templateId)) impact = 'high';

  return {
    templateId: role.templateId,
    name: role.name,
    isPrivileged: role.isPrivileged,
    impact,
    themes: [...high, ...medium],
    pimRecommended: impact === 'high',
    known: true,
  };
}

const catalog = new Map((atlas.roles as AtlasRole[]).map((r) => [r.templateId, classify(r)]));

/** Classification for a role template id; custom or unknown roles are treated as medium impact. */
export function classifyRole(templateId: string, displayName = ''): RoleClassification {
  const known = catalog.get(templateId.toLowerCase());
  if (known) return known;
  return {
    templateId,
    name: displayName || templateId,
    isPrivileged: false,
    impact: 'medium',
    themes: ['Custom role – not classified'],
    pimRecommended: false,
    known: false,
  };
}

/** Template ids that should only ever be held through PIM eligibility (the default for policy.requiredPimRoles). */
export const pimRecommendedRoles = (): string[] =>
  [...catalog.values()].filter((r) => r.pimRecommended).map((r) => r.templateId);
