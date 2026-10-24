import type { GraphResponse } from '../graph/client.js';
import type { Policy } from '../policy.js';
import { classifyRole, type Impact } from './roleCatalog.js';
import { isOk, ok, unavailableFrom, valueOf, type Section } from './section.js';

// Privilege exposure: which Entra roles the user holds – directly or through a role-assignable group – whether
// they're permanent or PIM-governed, and how much damage each could do. The "requires PIM" overlay is a separate
// finding computed from the same data.

export type AssignmentState = 'permanentActive' | 'timeBoundActive' | 'activated' | 'eligible';

export interface RoleAssignmentView {
  roleName: string;
  templateId: string;
  scope: string;
  state: AssignmentState;
  /** Assigned directly, or through a role-assignable group */
  via: 'direct' | 'group';
  /** The role-assignable group that holds the role, when known */
  groupName: string;
  endDateTime: string | null;
  impact: Impact;
  themes: string[];
  known: boolean;
  /** Tenant policy says this role must only be held through PIM eligibility */
  pimRequired: boolean;
  /** pimRequired, actively assigned (permanent or time-bound, not activated) and not an approved exception */
  pimDrift: boolean;
}

export interface PrivilegeView {
  assignments: RoleAssignmentView[];
  /** False when PIM schedules couldn't be read (typically no Entra ID P2) – every active role is then direct */
  pimDetail: boolean;
  isPimException: boolean;
  /** Lookups that failed, so the inventory may be missing roles */
  gaps: string[];
}

/** Role lookups for one principal: the user, or a role-assignable group they belong to */
export interface RoleResponses {
  schedules?: GraphResponse;
  assignments?: GraphResponse;
  eligibilities?: GraphResponse;
}

export interface GroupRoleResponses extends RoleResponses {
  groupName: string;
}

/* eslint-disable @typescript-eslint/no-explicit-any -- Graph payload shapes are mapped field by field below */
type Any = any;

const STATE_ORDER: Record<AssignmentState, number> = { permanentActive: 0, timeBoundActive: 1, activated: 2, eligible: 3 };
const IMPACT_ORDER: Record<Impact, number> = { high: 0, medium: 1, low: 2 };

function scopeOf(directoryScopeId: unknown): string {
  if (!directoryScopeId || directoryScopeId === '/') return 'Tenant';
  const s = String(directoryScopeId);
  return s.startsWith('/administrativeUnits/') ? 'Administrative unit' : s;
}

function toAssignment(a: Any, state: AssignmentState, policy: Policy, isException: boolean, groupName = ''): RoleAssignmentView {
  const def = a.roleDefinition ?? {};
  const templateId = String(def.templateId ?? a.roleDefinitionId ?? '').toLowerCase();
  const role = classifyRole(templateId, def.displayName);
  const scope = scopeOf(a.directoryScopeId);
  // A role scoped to an administrative unit or single object can only reach part of the tenant
  const impact: Impact = scope !== 'Tenant' && role.impact === 'high' ? 'medium' : role.impact;
  const pimRequired = policy.requiredPimRoles.includes(templateId);
  const activeWithoutActivation = state === 'permanentActive' || state === 'timeBoundActive';
  return {
    roleName: def.displayName || role.name,
    templateId,
    scope,
    state,
    via: groupName || a.memberType === 'Group' ? 'group' : 'direct',
    groupName,
    endDateTime: a.endDateTime ?? null,
    impact,
    themes: role.themes,
    known: role.known,
    pimRequired,
    pimDrift: pimRequired && activeWithoutActivation && !isException,
  };
}

/** Collects one principal's roles; returns false when even the active-role lookup failed. */
function collect(
  r: RoleResponses,
  out: RoleAssignmentView[],
  gaps: string[],
  ctx: { policy: Policy; isException: boolean; groupName?: string; who: string },
): { ok: boolean; pimDetail: boolean; why?: ReturnType<typeof unavailableFrom> } {
  let pimDetail = true;
  if (isOk(r.schedules)) {
    for (const a of valueOf<Any>(r.schedules!)) {
      const state: AssignmentState = a.assignmentType === 'Activated' ? 'activated' : a.endDateTime ? 'timeBoundActive' : 'permanentActive';
      out.push(toAssignment(a, state, ctx.policy, ctx.isException, ctx.groupName));
    }
  } else if (isOk(r.assignments)) {
    // Without PIM there are no schedules: every assignment is permanent
    pimDetail = false;
    for (const a of valueOf<Any>(r.assignments!)) out.push(toAssignment(a, 'permanentActive', ctx.policy, ctx.isException, ctx.groupName));
  } else {
    return { ok: false, pimDetail: false, why: unavailableFrom(r.schedules ?? r.assignments) };
  }

  if (isOk(r.eligibilities)) {
    for (const a of valueOf<Any>(r.eligibilities!)) out.push(toAssignment(a, 'eligible', ctx.policy, ctx.isException, ctx.groupName));
  } else {
    const why = unavailableFrom(r.eligibilities);
    // No P2 means no PIM, so there are no eligibilities to miss; anything else leaves the inventory incomplete
    if (pimDetail || why.reason !== 'notLicensed') gaps.push(`Eligible (PIM) roles ${ctx.who} couldn't be read: ${why.message}`);
  }
  return { ok: true, pimDetail };
}

export function buildPrivilege(
  user: RoleResponses,
  userId: string,
  policy: Policy,
  groups: { results: GroupRoleResponses[]; gaps: string[] } = { results: [], gaps: [] },
): Section<PrivilegeView> {
  const isException = policy.pimExceptions.includes(userId.toLowerCase());
  const assignments: RoleAssignmentView[] = [];
  const gaps: string[] = [...groups.gaps];

  const own = collect(user, assignments, gaps, { policy, isException, who: 'for this user' });
  if (!own.ok) return own.why!;

  // Group-held roles; skip any the user-level PIM view already reported as inherited from a group
  const seen = new Set(assignments.filter((a) => a.via === 'group').map((a) => `${a.templateId}|${a.scope}|${a.state}`));
  for (const g of groups.results) {
    const found: RoleAssignmentView[] = [];
    const res = collect(g, found, gaps, { policy, isException, groupName: g.groupName, who: `through ${g.groupName}` });
    if (!res.ok) {
      gaps.push(`Roles held through ${g.groupName} couldn't be read: ${res.why!.message}`);
      continue;
    }
    assignments.push(...found.filter((a) => !seen.has(`${a.templateId}|${a.scope}|${a.state}`)));
  }

  assignments.sort((a, b) => IMPACT_ORDER[a.impact] - IMPACT_ORDER[b.impact] || STATE_ORDER[a.state] - STATE_ORDER[b.state] || a.roleName.localeCompare(b.roleName));
  return ok({ assignments, pimDetail: own.pimDetail, isPimException: isException, gaps });
}

/** Holds (or can activate) a role that reaches the whole tenant's identities, apps or policies. */
export const isPrivileged = (p: Section<PrivilegeView>): boolean =>
  p.status === 'ok' && p.data.assignments.some((a) => a.impact === 'high');
