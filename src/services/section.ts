import type { GraphResponse } from '../graph/client.js';

export type Unavailable = {
  status: 'unavailable';
  reason: 'notLicensed' | 'forbidden' | 'notFound' | 'disabled' | 'error';
  message: string;
};

/** A panel's data, or why it couldn't be loaded – so one missing licence doesn't blank the whole page. */
export type Section<T> = { status: 'ok'; data: T } | Unavailable;

export const ok = <T>(data: T): Section<T> => ({ status: 'ok', data });

const LICENCE_CODES = new Set([
  'Authentication_RequestFromNonPremiumTenantOrB2CTenant',
  'Authentication_RequestFromUnsupportedUserRole',
  'Authorization_IdentityProtectionNotLicensed',
]);

export function unavailableFrom(res: GraphResponse | undefined): Unavailable {
  if (!res) return { status: 'unavailable', reason: 'error', message: 'No response from Microsoft Graph.' };
  const err = (res.body as { error?: { code?: string; message?: string } } | undefined)?.error;
  const code = err?.code ?? '';
  if (LICENCE_CODES.has(code) || /premium|licen[cs]e/i.test(err?.message ?? '')) {
    return {
      status: 'unavailable',
      reason: 'notLicensed',
      message: 'This data needs a Microsoft Entra ID P1/P2 licence in the tenant.',
    };
  }
  if (res.status === 401 || res.status === 403) {
    return {
      status: 'unavailable',
      reason: 'forbidden',
      message: "The app's managed identity hasn't been granted the Graph permission for this data.",
    };
  }
  if (res.status === 404) return { status: 'unavailable', reason: 'notFound', message: 'No data found.' };
  return { status: 'unavailable', reason: 'error', message: err?.message ?? `Graph returned HTTP ${res.status}.` };
}

export const isOk = (res: GraphResponse | undefined): boolean =>
  !!res && res.status >= 200 && res.status < 300;

export const valueOf = <T>(res: GraphResponse): T[] => (res.body as { value?: T[] } | null)?.value ?? [];
