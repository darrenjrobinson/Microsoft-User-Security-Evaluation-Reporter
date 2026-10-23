import type { GraphResponse } from '../graph/client.js';
import type { Policy } from '../policy.js';
import { classifyRole, type Impact } from './roleCatalog.js';
import { isOk, ok, unavailableFrom, valueOf, type Section } from './section.js';

// Privilege exposure: which Entra roles the user holds, whether they're permanent or PIM-governed, and how much
// damage each could do. The "requires PIM" overlay is a separate finding computed from the same data.

export type AssignmentState = 'permanentActive' | 'timeBoundActive' | 'activated' | 'eligible';

export interface RoleAssignmentView {
  roleName: string;
  templateId: string;
  scope: string;
  state: AssignmentState;
  /** Assigned directly, or through a role-assignable group */
  via: 'direct' | 'group';
  endDateTime: string | null;
  impact: Impact;
  themes: string[];
  known: boolean;
  /** Tenant policy says this role must only be held through PIM eligibility */
  pimRequired: boolean;
  /** pimRequired, held permanently and not an approved exception */
  pimDrift: boolean;
}

export interface PrivilegeView {
  assignments: RoleAssignmentView[];
  /** False when PIM schedules couldn't be read (typically no Entra ID P2) – every active role is then direct */
  pimDetail: boolean;
  isPimException: boolean;
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

function toAssignment(a: Any, state: AssignmentState, policy: Policy, isException: boolean): RoleAssignmentView {
  const def = a.roleDefinition ?? {};
  const templateId = String(def.templateId ?? a.roleDefinitionId ?? '').toLowerCase();
  const role = classifyRole(templateId, def.displayName);
  const scope = scopeOf(a.directoryScopeId);
  // A role scoped to an administrative unit or single object can only reach part of the tenant
  const impact: Impact = scope !== 'Tenant' && role.impact === 'high' ? 'medium' : role.impact;
  const pimRequired = policy.requiredPimRoles.includes(templateId);
  return {
    roleName: def.displayName || role.name,
    templateId,
    scope,
    state,
    via: a.memberType === 'Group' ? 'group' : 'direct',
    endDateTime: a.endDateTime ?? null,
    impact,
    themes: role.themes,
    known: role.known,
    pimRequired,
    pimDrift: pimRequired && state === 'permanentActive' && !isException,
  };
}

export function buildPrivilege(
  responses: { schedules?: GraphResponse; assignments?: GraphResponse; eligibilities?: GraphResponse },
  userId: string,
  policy: Policy,
): Section<PrivilegeView> {
  const isException = policy.pimExceptions.includes(userId.toLowerCase());
  const assignments: RoleAssignmentView[] = [];
  let pimDetail = true;

  if (isOk(responses.schedules)) {
    for (const a of valueOf<Any>(responses.schedules!)) {
      const state: AssignmentState = a.assignmentType === 'Activated' ? 'activated' : a.endDateTime ? 'timeBoundActive' : 'permanentActive';
      assignments.push(toAssignment(a, state, policy, isException));
    }
  } else if (isOk(responses.assignments)) {
    // Without PIM there are no schedules: every assignment is permanent
    pimDetail = false;
    for (const a of valueOf<Any>(responses.assignments!)) assignments.push(toAssignment(a, 'permanentActive', policy, isException));
  } else {
    return unavailableFrom(responses.schedules ?? responses.assignments);
  }

  if (isOk(responses.eligibilities)) {
    for (const a of valueOf<Any>(responses.eligibilities!)) assignments.push(toAssignment(a, 'eligible', policy, isException));
  }

  assignments.sort((a, b) => IMPACT_ORDER[a.impact] - IMPACT_ORDER[b.impact] || STATE_ORDER[a.state] - STATE_ORDER[b.state] || a.roleName.localeCompare(b.roleName));
  return ok({ assignments, pimDetail, isPimException: isException });
}

/** Holds (or can activate) a role that reaches the whole tenant's identities, apps or policies. */
export const isPrivileged = (p: Section<PrivilegeView>): boolean =>
  p.status === 'ok' && p.data.assignments.some((a) => a.impact === 'high');
