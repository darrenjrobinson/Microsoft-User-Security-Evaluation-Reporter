import { ok, type Section } from './section.js';

// Have I Been Pwned v3 – https://haveibeenpwned.com/API/v3
// Microsoft Graph never exposes a user's password or hash, so instead of the original on-prem
// NTLM-hash check we look up the user's email address in HIBP breaches and pastes. These are the
// same endpoints Darren's @darrenjrobinson/hibp-mcp server wraps for AI assistants.

const HIBP_ROOT = 'https://haveibeenpwned.com/api/v3';
const MAX_RETRIES = 2;

interface HibpBreach {
  Name: string;
  Title: string;
  Domain: string;
  BreachDate: string;
  DataClasses: string[];
  IsVerified: boolean;
  IsSensitive?: boolean;
}

export interface BreachView {
  name: string;
  title: string;
  domain: string;
  breachDate: string;
  dataClasses: string[];
  includesPasswords: boolean;
  isVerified: boolean;
}

export interface HibpView {
  account: string;
  breaches: BreachView[];
  pasteCount: number;
}

export type HibpLookup = (account: string) => Promise<Section<HibpView>>;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export function createHibpService(opts: { apiKey?: string; userAgent: string; fetchImpl?: typeof fetch }): HibpLookup {
  const fetchImpl = opts.fetchImpl ?? fetch;

  async function call<T>(path: string): Promise<{ status: number; body: T | null }> {
    for (let attempt = 0; ; attempt++) {
      const res = await fetchImpl(`${HIBP_ROOT}${path}`, {
        headers: { 'hibp-api-key': opts.apiKey ?? '', 'user-agent': opts.userAgent, accept: 'application/json' },
      });
      if (res.status === 429 && attempt < MAX_RETRIES) {
        await sleep((Number(res.headers.get('retry-after')) || 2) * 1000);
        continue;
      }
      if (res.status === 404) return { status: 404, body: null };
      if (!res.ok) return { status: res.status, body: null };
      return { status: res.status, body: (await res.json()) as T };
    }
  }

  return async function lookup(account) {
    if (!opts.apiKey) {
      return { status: 'unavailable', reason: 'disabled', message: 'No Have I Been Pwned API key is configured.' };
    }
    const encoded = encodeURIComponent(account);
    const [breaches, pastes] = await Promise.all([
      call<HibpBreach[]>(`/breachedaccount/${encoded}?truncateResponse=false`),
      call<unknown[]>(`/pasteaccount/${encoded}`),
    ]);
    if (breaches.status !== 200 && breaches.status !== 404) {
      return {
        status: 'unavailable',
        reason: breaches.status === 401 || breaches.status === 403 ? 'forbidden' : 'error',
        message: `Have I Been Pwned returned HTTP ${breaches.status}.`,
      };
    }
    return ok({
      account,
      breaches: (breaches.body ?? []).map(toBreachView).sort((a, b) => b.breachDate.localeCompare(a.breachDate)),
      pasteCount: pastes.body?.length ?? 0,
    });
  };
}

export function toBreachView(b: HibpBreach): BreachView {
  return {
    name: b.Name,
    title: b.Title,
    domain: b.Domain,
    breachDate: b.BreachDate,
    dataClasses: b.DataClasses,
    includesPasswords: b.DataClasses.some((c) => /password/i.test(c)),
    isVerified: b.IsVerified,
  };
}
