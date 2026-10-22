import type { GraphClient } from '../graph/client.js';
import { queries } from '../graph/queries.js';

export type AccountType = 'Hybrid' | 'Cloud' | 'B2B';

export interface GraphUserSummary {
  id: string;
  displayName: string;
  userPrincipalName: string;
  mail?: string | null;
  department?: string | null;
  jobTitle?: string | null;
  userType?: string | null;
  onPremisesSyncEnabled?: boolean | null;
  accountEnabled?: boolean | null;
}

export interface UserSearchResult {
  id: string;
  displayName: string;
  userPrincipalName: string;
  mail: string;
  department: string;
  jobTitle: string;
  accountType: AccountType;
  accountEnabled: boolean;
}

/** Hybrid = synced from AD by Entra Connect, B2B = guest, otherwise cloud-only (as in the original). */
export function accountTypeOf(u: Pick<GraphUserSummary, 'userType' | 'onPremisesSyncEnabled'>): AccountType {
  if (u.userType?.toLowerCase() === 'guest') return 'B2B';
  return u.onPremisesSyncEnabled ? 'Hybrid' : 'Cloud';
}

export function toSearchResult(u: GraphUserSummary): UserSearchResult {
  return {
    id: u.id,
    displayName: u.displayName,
    userPrincipalName: u.userPrincipalName,
    mail: u.mail ?? '',
    department: u.department ?? '',
    jobTitle: u.jobTitle ?? '',
    accountType: accountTypeOf(u),
    accountEnabled: u.accountEnabled ?? true,
  };
}

export function createUserSearchService(graph: GraphClient) {
  return async function searchUsers(text: string): Promise<UserSearchResult[]> {
    const { url, headers } = queries.searchUsers(text);
    const res = await graph.get<{ value: GraphUserSummary[] }>(url, headers);
    return res.body.value.map(toSearchResult);
  };
}
