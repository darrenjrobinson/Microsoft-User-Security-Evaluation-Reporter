import type { GraphClient, GraphRequest, GraphResponse } from '../graph/client.js';
import { toGraphError } from '../graph/client.js';
import * as f from './fixtures.js';

const notFound: GraphResponse = { status: 404, body: { error: { code: 'Request_ResourceNotFound', message: 'Not found' } } };
const list = (value: unknown[]): GraphResponse => ({ status: 200, body: { value } });

function param(url: URL, name: string): string {
  return url.searchParams.get(name) ?? '';
}

/** Answers the fixed queries in graph/queries.ts from fixtures.ts. */
export function route(path: string): GraphResponse {
  const url = new URL(path, 'https://graph.mock/v1.0/');
  const p = url.pathname.replace(/^\/v1\.0/, '');
  let m: RegExpMatchArray | null;

  if (p === '/security/secureScores') return list(f.secureScores);

  if (p === '/identityProtection/riskDetections') {
    const filter = param(url, '$filter');
    const byUser = /userId eq '([^']+)'/.exec(filter)?.[1];
    if (byUser) return list(f.riskDetections.filter((d) => d.userId === byUser));
    return list(f.riskDetections.filter((d) => d.riskState === 'atRisk'));
  }

  if ((m = p.match(/^\/identityProtection\/riskyUsers\/([^/]+)$/))) {
    const r = f.riskyUsers[m[1]!];
    return r ? { status: 200, body: r } : notFound;
  }

  if (p === '/users') {
    const term = /"displayName:([^"]*)"/.exec(param(url, '$search'))?.[1]?.trim().toLowerCase() ?? '';
    const words = term.split(' ').filter(Boolean);
    const hits = f.users.filter((u) => {
      const hay = `${u.displayName} ${u.userPrincipalName} ${u.mail ?? ''}`.toLowerCase();
      return words.every((w) => hay.includes(w));
    });
    return list(hits.map(({ manager: _manager, ...u }) => u));
  }

  if ((m = p.match(/^\/users\/([^/]+)$/))) {
    const u = f.users.find((x) => x.id === m![1]);
    return u ? { status: 200, body: u } : notFound;
  }

  if ((m = p.match(/^\/users\/([^/]+)\/registeredDevices/))) return list(f.devices[m[1]!] ?? []);

  if (p === '/auditLogs/signIns') {
    const id = /userId eq '([^']+)'/.exec(param(url, '$filter'))?.[1] ?? '';
    return list(f.signIns[id] ?? []);
  }

  if (p === '/auditLogs/directoryAudits') {
    const id = /t\/id eq '([^']+)'/.exec(param(url, '$filter'))?.[1] ?? '';
    return list(f.ssprEvents[id] ?? []);
  }

  if ((m = p.match(/^\/reports\/authenticationMethods\/userRegistrationDetails\/([^/]+)$/))) {
    const r = f.registrationDetails[m[1]!];
    return r ? { status: 200, body: r } : notFound;
  }

  return { status: 400, body: { error: { code: 'BadRequest', message: `Mock has no route for ${p}` } } };
}

export class MockGraphClient implements GraphClient {
  public readonly calls: string[] = [];

  async get<T>(url: string): Promise<GraphResponse<T>> {
    this.calls.push(url);
    const res = route(url);
    if (res.status >= 400) throw toGraphError(res);
    return res as GraphResponse<T>;
  }

  async batch(requests: GraphRequest[]): Promise<Map<string, GraphResponse>> {
    this.calls.push(...requests.map((r) => r.url));
    return new Map(requests.map((r) => [r.id, route(r.url)]));
  }
}

/** A fetch stand-in for the HIBP service that serves fixtures. */
export const mockHibpFetch: typeof fetch = async (input) => {
  const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
  const [, kind, account] = /\/api\/v3\/(breachedaccount|pasteaccount)\/([^/?]+)/.exec(url.pathname) ?? [];
  const key = decodeURIComponent(account ?? '').toLowerCase();
  const data = kind === 'breachedaccount' ? f.hibpBreaches[key] : kind === 'pasteaccount' ? f.hibpPastes[key] : undefined;
  return data
    ? new Response(JSON.stringify(data), { status: 200, headers: { 'content-type': 'application/json' } })
    : new Response(null, { status: 404 });
};
