import { z } from 'zod';
import { isObjectId } from './graph/queries.js';
import { pimRecommendedRoles } from './services/roleCatalog.js';

// Tenant-tunable overlays, supplied as JSON in the POLICY_JSON app setting. Everything is optional:
// "requires PIM", break-glass accounts and review thresholds are partly local governance decisions.

const objectId = z
  .string()
  .refine(isObjectId, 'must be an object id (GUID)')
  .transform((v) => v.toLowerCase());
const idOrUpn = z
  .string()
  .min(3)
  .transform((v) => v.toLowerCase());
const count = z.number().int().positive();

const policySchema = z
  .object({
    /** Role template ids that must only be held through PIM eligibility. Defaults to every high-impact role. */
    requiredPimRoles: z.array(objectId).optional(),
    /** User object ids allowed to hold required-PIM roles directly (e.g. break-glass) */
    pimExceptions: z.array(objectId).default([]),
    /** Emergency access accounts, by object id or UPN */
    breakGlassAccounts: z.array(idOrUpn).default([]),
    /** Members of these groups are treated as emergency access accounts */
    breakGlassGroupIds: z.array(objectId).default([]),
    /** Service / shared accounts that the per-user checks don't apply to, by object id or UPN */
    serviceAccounts: z.array(idOrUpn).default([]),
    /** Groups that grant access to sensitive resources (tier 0, finance, HR…) */
    sensitiveGroupIds: z.array(objectId).default([]),
    membershipThresholds: z
      .object({ directGroups: count.default(75), transitiveGroups: count.default(200), sensitiveGroups: count.default(3) })
      .strict()
      .prefault({}),
    /** Guests invited (30 days) + guests sponsored before the footprint needs review */
    guestThresholds: z.object({ warning: count.default(10), danger: count.default(50) }).strict().prefault({}),
  })
  .strict();

export type PolicyInput = z.input<typeof policySchema>;
export type Policy = Omit<z.output<typeof policySchema>, 'requiredPimRoles'> & { requiredPimRoles: string[] };

export function parsePolicy(json?: string): Policy {
  let raw: unknown = {};
  if (json?.trim()) {
    try {
      raw = JSON.parse(json);
    } catch {
      throw new Error('POLICY_JSON is not valid JSON');
    }
  }
  const parsed = policySchema.safeParse(raw);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new Error(`POLICY_JSON is invalid: ${issue?.path.join('.') || '(root)'} ${issue?.message ?? ''}`.trim());
  }
  return { ...parsed.data, requiredPimRoles: parsed.data.requiredPimRoles ?? pimRecommendedRoles() };
}
