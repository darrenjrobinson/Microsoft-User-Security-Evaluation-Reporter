import type { GraphBinary, GraphClient, GraphRequest, GraphResponse, GraphVersion } from '../graph/client.js';
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
  const p = url.pathname.replace(/^\/(v1\.0|beta)/, '');
  const filter = param(url, '$filter');
  const principal = /principalId eq '([^']+)'/.exec(filter)?.[1] ?? '';
  let m: RegExpMatchArray | null;

  if (p === '/security/secureScores') return list(f.secureScores);
  if (p === '/subscribedSkus') return list(f.subscribedSkus);

  if (p === '/roleManagement/directory/roleAssignmentScheduleInstances') return list(f.roleSchedules[principal] ?? []);
  if (p === '/roleManagement/directory/roleAssignments') return list(f.roleAssignments[principal] ?? []);
  if (p === '/roleManagement/directory/roleEligibilityScheduleInstances') return list(f.roleEligibilities[principal] ?? []);

  if (p === '/policies/authenticationMethodsPolicy') return { status: 200, body: f.authMethodsPolicy };
  if (p === '/policies/identitySecurityDefaultsEnforcementPolicy') return { status: 200, body: f.securityDefaults };

  if ((m = p.match(/^\/users\/([^/]+)\/authentication\/methods$/))) return list(f.authMethods[m[1]!] ?? []);
  if ((m = p.match(/^\/users\/([^/]+)\/directReports$/))) {
    return { status: 200, body: { '@odata.count': f.directReportCounts[m[1]!] ?? 0, value: [] } };
  }
  if ((m = p.match(/^\/users\/([^/]+)\/ownedObjects$/))) return list(f.ownedObjects[m[1]!] ?? []);
  if ((m = p.match(/^\/users\/([^/]+)\/sponsorOf$/))) return list(f.sponsorOf[m[1]!] ?? []);
  if ((m = p.match(/^\/users\/([^/]+)\/memberOf$/))) return list(f.memberOf[m[1]!] ?? []);
  if ((m = p.match(/^\/users\/([^/]+)\/transitiveMemberOf\/microsoft\.graph\.group$/))) {
    return { status: 200, body: { '@odata.count': f.transitiveGroupCounts[m[1]!] ?? 0, value: [] } };
  }

  if (p === '/identityProtection/riskDetections') {
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
    if (param(url, '$select') === 'signInActivity') {
      const a = f.signInActivity[m[1]!];
      return a ? { status: 200, body: { id: m[1], signInActivity: a } } : notFound;
    }
    const u = f.users.find((x) => x.id === m![1]);
    return u ? { status: 200, body: u } : notFound;
  }

  if ((m = p.match(/^\/users\/([^/]+)\/registeredDevices/))) return list(f.devices[m[1]!] ?? []);

  if (p === '/auditLogs/signIns') {
    const id = /userId eq '([^']+)'/.exec(param(url, '$filter'))?.[1] ?? '';
    return list(f.signIns[id] ?? []);
  }

  if (p === '/auditLogs/directoryAudits') {
    const target = /t\/id eq '([^']+)'/.exec(filter)?.[1] ?? '';
    const initiator = /initiatedBy\/user\/id eq '([^']+)'/.exec(filter)?.[1] ?? '';
    if (filter.includes("'Authentication Methods'")) return list(f.methodAudits[target] ?? []);
    if (filter.includes("'Invite external user'")) return list(f.guestInvites[initiator] ?? []);
    return list(f.ssprEvents[target] ?? []);
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

  async getBinary(url: string): Promise<GraphBinary> {
    this.calls.push(url);
    // Only the fixed-size photo exists in the demo tenant, so the default-photo fallback is never needed
    const id = /^\/users\/([^/]+)\/photos\/120x120\/\$value$/.exec(url)?.[1];
    const photo = id ? f.photos[id] : undefined;
    return photo
      ? { status: 200, contentType: 'image/png', body: Buffer.from(photo, 'base64') }
      : { status: 404, contentType: 'application/json', body: Buffer.alloc(0) };
  }

  async batch(requests: GraphRequest[], opts: { version?: GraphVersion } = {}): Promise<Map<string, GraphResponse>> {
    const prefix = opts.version === 'beta' ? '/beta' : '';
    this.calls.push(...requests.map((r) => `${prefix}${r.url}`));
    return new Map(requests.map((r) => [r.id, route(`${prefix}${r.url}`)]));
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
