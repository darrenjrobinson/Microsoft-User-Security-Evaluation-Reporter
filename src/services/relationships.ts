import type { GraphResponse } from '../graph/client.js';
import type { Paged } from '../graph/paging.js';
import type { Policy } from '../policy.js';
import { isOk, ok, unavailableFrom, valueOf, type Section } from './section.js';

// What else the user effectively controls or expands: objects they own, guests they bring in and sponsor,
// and how far their group memberships reach.

/* eslint-disable @typescript-eslint/no-explicit-any -- Graph payload shapes are mapped field by field below */
type Any = any;

export type OwnedKind = 'application' | 'servicePrincipal' | 'agent' | 'roleAssignableGroup' | 'team' | 'm365Group' | 'securityGroup' | 'mailGroup' | 'other';

export interface OwnedObjectView {
  id: string;
  displayName: string;
  kind: OwnedKind;
  /** Flagged in policy.sensitiveGroupIds */
  sensitive: boolean;
}

export interface OwnershipView {
  objects: OwnedObjectView[];
  counts: Partial<Record<OwnedKind, number>>;
  /** False when more pages exist than were read – counts are lower bounds */
  complete: boolean;
}

export interface GuestGovernanceView {
  sponsored: { id: string; displayName: string; userPrincipalName: string }[] | null;
  invites: { id: string; activityDateTime: string; invitee: string }[] | null;
  /** Distinct guests sponsored or successfully invited in the last 30 days */
  footprint: number;
  /** False when a source was unavailable or truncated – footprint is a lower bound */
  complete: boolean;
  /** Why the footprint may be incomplete */
  gaps: string[];
}

export interface MembershipView {
  directGroups: number;
  transitiveGroups: number | null;
  m365Groups: number;
  adminUnits: string[];
  directoryRoles: string[];
  roleAssignableGroups: { id: string; displayName: string }[];
  sensitiveGroups: { id: string; displayName: string }[];
  /** Thresholds this user exceeds, for display */
  exceeded: string[];
  /** False when more memberships exist than were read – counts are lower bounds */
  complete: boolean;
}

const typeOf = (o: Any) => String(o['@odata.type'] ?? '').replace(/^#microsoft\.graph\./, '');
const str = (v: unknown) => (typeof v === 'string' ? v : '');

function groupKind(g: Any): OwnedKind {
  if (g.isAssignableToRole) return 'roleAssignableGroup';
  const unified = Array.isArray(g.groupTypes) && g.groupTypes.includes('Unified');
  if (unified) return Array.isArray(g.resourceProvisioningOptions) && g.resourceProvisioningOptions.includes('Team') ? 'team' : 'm365Group';
  return g.securityEnabled ? 'securityGroup' : 'mailGroup';
}

function ownedKind(o: Any): OwnedKind {
  const t = typeOf(o);
  if (/^agent/i.test(t)) return 'agent';
  if (t === 'application') return 'application';
  if (t === 'servicePrincipal') return 'servicePrincipal';
  if (t === 'group') return groupKind(o);
  return 'other';
}

export function buildOwnership({ res, complete }: Paged, policy: Policy): Section<OwnershipView> {
  if (!isOk(res)) {
    const why = unavailableFrom(res);
    // Graph documents /users/{id}/ownedObjects as delegated-only, so an app-only token may be refused
    return why.reason === 'forbidden'
      ? { ...why, message: "Microsoft Graph doesn't return a user's owned objects to this app's managed identity (application permissions)." }
      : why;
  }
  const objects = valueOf<Any>(res!).map((o) => ({
    id: str(o.id),
    displayName: str(o.displayName) || str(o.id),
    kind: ownedKind(o),
    sensitive: policy.sensitiveGroupIds.includes(str(o.id).toLowerCase()),
  }));
  const counts: Partial<Record<OwnedKind, number>> = {};
  for (const o of objects) counts[o.kind] = (counts[o.kind] ?? 0) + 1;
  return ok({ objects, counts, complete });
}

const succeeded = (a: Any) => !a.result || a.result === 'success';

export function buildGuests(sponsorOf: Paged, invites: Paged): Section<GuestGovernanceView> {
  if (!isOk(sponsorOf.res) && !isOk(invites.res)) return unavailableFrom(sponsorOf.res ?? invites.res);
  const gaps: string[] = [];
  let sponsored: GuestGovernanceView['sponsored'] = null;
  if (isOk(sponsorOf.res)) {
    sponsored = valueOf<Any>(sponsorOf.res!)
      .filter((o) => typeOf(o) === 'user')
      .map((u) => ({ id: str(u.id), displayName: str(u.displayName), userPrincipalName: str(u.userPrincipalName) }));
    if (!sponsorOf.complete) gaps.push('Only the first pages of sponsored guests were read.');
  } else {
    const why = unavailableFrom(sponsorOf.res);
    // Graph documents /users/{id}/sponsorOf as delegated-only
    gaps.push(
      why.reason === 'forbidden'
        ? "Guests this user sponsors aren't available to the app's managed identity (application permissions)."
        : `Guests this user sponsors couldn't be read: ${why.message}`,
    );
  }
  let inviteList: GuestGovernanceView['invites'] = null;
  if (isOk(invites.res)) {
    // A failed invitation didn't bring a guest in
    inviteList = valueOf<Any>(invites.res!)
      .filter(succeeded)
      .map((a) => {
        const t = a.targetResources?.[0] ?? {};
        return { id: str(t.id), activityDateTime: str(a.activityDateTime), invitee: str(t.userPrincipalName) || str(t.displayName) || str(t.id) };
      })
      .sort((a, b) => b.activityDateTime.localeCompare(a.activityDateTime));
    if (!invites.complete) gaps.push('Only the first pages of guest invitations were read.');
  } else {
    gaps.push(`Guest invitations couldn't be read: ${unavailableFrom(invites.res).message}`);
  }
  const ids = new Set([...(sponsored ?? []).map((s) => s.id), ...(inviteList ?? []).map((i) => i.id || i.invitee)]);
  return ok({ sponsored, invites: inviteList, footprint: ids.size, complete: gaps.length === 0, gaps });
}

export function buildMembership({ res: memberOf, complete }: Paged, transitive: GraphResponse | undefined, policy: Policy): Section<MembershipView> {
  if (!isOk(memberOf)) return unavailableFrom(memberOf);
  const items = valueOf<Any>(memberOf!);
  const groups = items.filter((o) => typeOf(o) === 'group');
  const transitiveGroups = isOk(transitive) ? Number((transitive!.body as Any)?.['@odata.count']) : NaN;
  const named = (g: Any) => ({ id: str(g.id), displayName: str(g.displayName) || str(g.id) });
  const view: MembershipView = {
    directGroups: groups.length,
    transitiveGroups: Number.isFinite(transitiveGroups) ? transitiveGroups : null,
    m365Groups: groups.filter((g) => Array.isArray(g.groupTypes) && g.groupTypes.includes('Unified')).length,
    adminUnits: items.filter((o) => typeOf(o) === 'administrativeUnit').map((o) => str(o.displayName)),
    directoryRoles: items.filter((o) => typeOf(o) === 'directoryRole').map((o) => str(o.displayName)),
    roleAssignableGroups: groups.filter((g) => g.isAssignableToRole).map(named),
    sensitiveGroups: groups.filter((g) => policy.sensitiveGroupIds.includes(str(g.id).toLowerCase())).map(named),
    exceeded: [],
    complete,
  };
  const t = policy.membershipThresholds;
  if (view.directGroups > t.directGroups) view.exceeded.push(`${view.directGroups} direct groups (review above ${t.directGroups})`);
  if ((view.transitiveGroups ?? 0) > t.transitiveGroups) view.exceeded.push(`${view.transitiveGroups} groups including nested (review above ${t.transitiveGroups})`);
  if (view.sensitiveGroups.length >= t.sensitiveGroups) view.exceeded.push(`${view.sensitiveGroups.length} sensitive groups (review at ${t.sensitiveGroups})`);
  return ok(view);
}

/** Membership of any group listed in policy.breakGlassGroupIds */
export const inBreakGlassGroup = (memberOf: GraphResponse | undefined, policy: Policy): boolean =>
  policy.breakGlassGroupIds.length > 0 &&
  isOk(memberOf) &&
  valueOf<Any>(memberOf!).some((o) => policy.breakGlassGroupIds.includes(str(o.id).toLowerCase()));
