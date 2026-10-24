import type { GraphClient } from '../graph/client.js';
import { queries } from '../graph/queries.js';

// Licences are a quick read on what kind of worker this is: a frontline (F-SKU) licence next to an admin role is
// a very different story from an E5 knowledge worker.
//
// A user's licences come from user.assignedLicenses (SKU ids, direct and group-assigned). /users/{id}/licenseDetails
// would give names directly but doesn't support application permissions, so ids are resolved through the tenant's
// /subscribedSkus, which rarely changes and is cached.

export interface LicenceView {
  skuId: string;
  skuPartNumber: string;
  name: string;
  /** Frontline worker SKU (F1 / F3) */
  frontline: boolean;
}

/* eslint-disable @typescript-eslint/no-explicit-any -- Graph payload shapes are mapped field by field below */
type Any = any;

// Friendly names for common SKUs; anything else is shown by its part number
const SKU_NAMES: Record<string, string> = {
  SPE_E3: 'Microsoft 365 E3',
  SPE_E5: 'Microsoft 365 E5',
  SPE_F1: 'Microsoft 365 F3',
  M365_F1: 'Microsoft 365 F1',
  M365_F1_COMM: 'Microsoft 365 F1',
  DEVELOPERPACK_E5: 'Microsoft 365 E5 (developer)',
  SPB: 'Microsoft 365 Business Premium',
  O365_BUSINESS_PREMIUM: 'Microsoft 365 Business Standard',
  O365_BUSINESS_ESSENTIALS: 'Microsoft 365 Business Basic',
  STANDARDPACK: 'Office 365 E1',
  ENTERPRISEPACK: 'Office 365 E3',
  ENTERPRISEPREMIUM: 'Office 365 E5',
  DESKLESSPACK: 'Office 365 F3',
  AAD_PREMIUM: 'Microsoft Entra ID P1',
  AAD_PREMIUM_P2: 'Microsoft Entra ID P2',
  EMS: 'Enterprise Mobility + Security E3',
  EMSPREMIUM: 'Enterprise Mobility + Security E5',
  INTUNE_A: 'Microsoft Intune Plan 1',
  POWER_BI_PRO: 'Power BI Pro',
  POWER_BI_STANDARD: 'Power BI (free)',
  FLOW_FREE: 'Power Automate (free)',
  TEAMS_EXPLORATORY: 'Teams Exploratory',
  Microsoft_Teams_Enterprise_New: 'Microsoft Teams Enterprise',
  WIN_DEF_ATP: 'Microsoft Defender for Endpoint',
  ATP_ENTERPRISE: 'Defender for Office 365 Plan 1',
  VISIOCLIENT: 'Visio Plan 2',
  PROJECTPREMIUM: 'Project Plan 5',
};

const FRONTLINE = /(^|_)F[13](_|$)|DESKLESS/i;

/** A licence by SKU id; partNumber is empty when the tenant catalog couldn't resolve it. */
export function toLicence(skuId: string, skuPartNumber = ''): LicenceView {
  return {
    skuId,
    skuPartNumber,
    name: SKU_NAMES[skuPartNumber] ?? (skuPartNumber || `Unrecognised licence (${skuId})`),
    frontline: FRONTLINE.test(skuPartNumber),
  };
}

/** The user's assigned licences, named through the tenant's SKU catalog (null = catalog unavailable). */
export function licencesOf(user: Any, catalog: Map<string, string> | null): LicenceView[] {
  const assigned: Any[] = Array.isArray(user.assignedLicenses) ? user.assignedLicenses : [];
  return assigned
    .map((l) => String(l.skuId ?? '').toLowerCase())
    .filter(Boolean)
    .map((id) => toLicence(id, catalog?.get(id) ?? ''))
    .sort((a, b) => a.name.localeCompare(b.name));
}

const TTL_MS = 6 * 3_600_000;

/** skuId → skuPartNumber for the tenant, cached; null when it can't be read (names then fall back to ids). */
export function createSkuCatalog(graph: GraphClient) {
  let cached: { at: number; value: Map<string, string> } | undefined;
  return async function getSkuCatalog(): Promise<Map<string, string> | null> {
    if (cached && Date.now() - cached.at < TTL_MS) return cached.value;
    try {
      const res = await graph.get<{ value?: { skuId?: string; skuPartNumber?: string }[] }>(queries.subscribedSkus());
      const value = new Map((res.body.value ?? []).filter((s) => s.skuId).map((s) => [String(s.skuId).toLowerCase(), String(s.skuPartNumber ?? '')]));
      cached = { at: Date.now(), value };
      return value;
    } catch {
      return null;
    }
  };
}
