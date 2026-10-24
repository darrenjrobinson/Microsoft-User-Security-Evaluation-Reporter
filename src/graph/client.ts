import { DefaultAzureCredential, type TokenCredential } from '@azure/identity';

const GRAPH_HOST = 'https://graph.microsoft.com';
const GRAPH_SCOPE = 'https://graph.microsoft.com/.default';
const MAX_RETRIES = 3;

/** v1.0 for everything except the few properties that only exist in beta (sign-in authenticationDetails). */
export type GraphVersion = 'v1.0' | 'beta';

export interface GraphRequest {
  id: string;
  method: 'GET';
  /** Path relative to the version root, e.g. `/users/{id}` */
  url: string;
  headers?: Record<string, string>;
}

export interface GraphResponse<T = unknown> {
  status: number;
  body: T;
}

export interface GraphBinary {
  status: number;
  contentType: string;
  body: Buffer;
}

export interface GraphClient {
  get<T>(url: string, headers?: Record<string, string>): Promise<GraphResponse<T>>;
  /** Raw bytes (e.g. a photo); never throws for 4xx so callers can treat "no photo" as normal */
  getBinary(url: string): Promise<GraphBinary>;
  /** Sends up to 20 requests as one JSON batch and returns the responses keyed by request id. */
  batch(requests: GraphRequest[], opts?: { version?: GraphVersion }): Promise<Map<string, GraphResponse>>;
}

export class GraphError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

interface GraphErrorBody {
  error?: { code?: string; message?: string };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export class HttpGraphClient implements GraphClient {
  constructor(
    private readonly credential: TokenCredential = new DefaultAzureCredential(),
    private readonly fetchImpl: typeof fetch = fetch,
  ) {}

  private async send(method: string, url: string, headers: Record<string, string> = {}, body?: unknown, version: GraphVersion = 'v1.0') {
    const token = await this.credential.getToken(GRAPH_SCOPE);
    if (!token) throw new GraphError(401, 'noToken', 'Could not acquire a Microsoft Graph token');

    for (let attempt = 0; ; attempt++) {
      const res = await this.fetchImpl(`${GRAPH_HOST}/${version}${url}`, {
        method,
        headers: {
          authorization: `Bearer ${token.token}`,
          accept: 'application/json',
          ...(body ? { 'content-type': 'application/json' } : {}),
          ...headers,
        },
        body: body ? JSON.stringify(body) : undefined,
      });
      if ((res.status === 429 || res.status === 503) && attempt < MAX_RETRIES) {
        const retryAfter = Number(res.headers.get('retry-after')) || 2 ** attempt;
        await sleep(Math.min(retryAfter, 10) * 1000);
        continue;
      }
      const json = res.status === 204 ? {} : await res.json().catch(() => ({}));
      return { status: res.status, body: json as unknown };
    }
  }

  async get<T>(url: string, headers?: Record<string, string>): Promise<GraphResponse<T>> {
    const res = await this.send('GET', url, headers);
    if (res.status >= 400) throw toGraphError(res);
    return res as GraphResponse<T>;
  }

  async getBinary(url: string): Promise<GraphBinary> {
    const token = await this.credential.getToken(GRAPH_SCOPE);
    if (!token) throw new GraphError(401, 'noToken', 'Could not acquire a Microsoft Graph token');
    const res = await this.fetchImpl(`${GRAPH_HOST}/v1.0${url}`, { headers: { authorization: `Bearer ${token.token}` } });
    const contentType = res.headers.get('content-type') ?? '';
    const body = res.ok ? Buffer.from(await res.arrayBuffer()) : Buffer.alloc(0);
    return { status: res.status, contentType, body };
  }

  async batch(requests: GraphRequest[], opts: { version?: GraphVersion } = {}): Promise<Map<string, GraphResponse>> {
    if (requests.length > 20) throw new Error('Graph JSON batching supports at most 20 requests');
    const res = await this.send('POST', '/$batch', {}, { requests }, opts.version);
    if (res.status >= 400) throw toGraphError(res);
    const responses = (res.body as { responses?: { id: string; status: number; body: unknown }[] }).responses ?? [];
    return new Map(responses.map((r) => [r.id, { status: r.status, body: r.body }]));
  }
}

export function toGraphError(res: GraphResponse): GraphError {
  const err = (res.body as GraphErrorBody)?.error;
  return new GraphError(res.status, err?.code ?? 'graphError', err?.message ?? `Graph request failed (${res.status})`);
}
