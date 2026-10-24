import type { Policy } from '../policy.js';
import type { AccountType } from './users.js';

// What kind of identity this is changes what a finding means: B2B guests' MFA is their home tenant's job,
// break-glass accounts are expected to be permanent Global Admins, service accounts are out of scope.

export interface IdentityView {
  accountType: AccountType;
  isBreakGlass: boolean;
  isServiceAccount: boolean;
  /** Holds or can activate a high-impact role */
  isPrivileged: boolean;
  /** Productivity workloads licensed to this account (a privileged account with these is a daily driver) */
  licensedWorkloads: string[];
}

/* eslint-disable @typescript-eslint/no-explicit-any -- Graph payload shapes are mapped field by field below */
type Any = any;

const WORKLOADS: Record<string, string> = {
  exchange: 'Mailbox',
  TeamspaceAPI: 'Teams',
  MicrosoftCommunicationsOnline: 'Teams',
  SharePoint: 'SharePoint / OneDrive',
};

export function licensedWorkloadsOf(user: Any): string[] {
  const plans: Any[] = Array.isArray(user.assignedPlans) ? user.assignedPlans : [];
  const names = plans.filter((p) => p.capabilityStatus === 'Enabled').map((p) => WORKLOADS[p.service]).filter(Boolean);
  return [...new Set(names)] as string[];
}

export function buildIdentity(
  user: { id: string; userPrincipalName: string; accountType: AccountType; raw: Any },
  policy: Policy,
  flags: { isPrivileged: boolean; inBreakGlassGroup: boolean },
): IdentityView {
  const keys = [user.id.toLowerCase(), user.userPrincipalName.toLowerCase()];
  return {
    accountType: user.accountType,
    isBreakGlass: flags.inBreakGlassGroup || keys.some((k) => policy.breakGlassAccounts.includes(k)),
    isServiceAccount: keys.some((k) => policy.serviceAccounts.includes(k)),
    isPrivileged: flags.isPrivileged,
    licensedWorkloads: licensedWorkloadsOf(user.raw),
  };
}
