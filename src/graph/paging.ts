import type { GraphClient, GraphRequest, GraphResponse } from './client.js';

// Inventories (owned objects, memberships, guests, audits) can span several pages. Follow @odata.nextLink,
// but only back to the same Graph path we asked for, so a response can't steer the app to another URL.

export const MAX_PAGES = 10;

export interface Paged {
  res: GraphResponse | undefined;
  /** False when pages remain unread (page cap, failed or unexpected continuation) – counts are lower bounds */
  complete: boolean;
}

const GRAPH_ORIGIN = 'https://graph.microsoft.com';

/** The relative v1.0 URL for a continuation link, or null if it points anywhere other than the original path. */
export function continuationOf(nextLink: string, request: GraphRequest): string | null {
  let url: URL;
  try {
    url = new URL(nextLink);
  } catch {
    return null;
  }
  const path = new URL(request.url, 'https://x').pathname;
  if (url.origin !== GRAPH_ORIGIN || url.pathname !== `/v1.0${path}`) return null;
  return `${path}${url.search}`;
}

const isOk = (res: GraphResponse | undefined) => !!res && res.status >= 200 && res.status < 300;
const nextLinkOf = (res: GraphResponse) => (res.body as { '@odata.nextLink'?: string } | null)?.['@odata.nextLink'];

export async function allPages(graph: GraphClient, request: GraphRequest, first: GraphResponse | undefined): Promise<Paged> {
  const body = (first?.body ?? {}) as { value?: unknown[]; '@odata.nextLink'?: string };
  // Nothing to page: an error, or a 2xx without a list (callers report that as missing data)
  if (!isOk(first) || !Array.isArray(body.value)) return { res: first, complete: true };
  const value = [...(body.value ?? [])];
  let link = body['@odata.nextLink'];
  let pages = 1;
  while (link && pages < MAX_PAGES) {
    const next = continuationOf(link, request);
    if (!next) break;
    try {
      const page = await graph.get<{ value?: unknown[]; '@odata.nextLink'?: string }>(next, request.headers);
      value.push(...(page.body.value ?? []));
      link = nextLinkOf(page);
      pages++;
    } catch {
      break;
    }
  }
  const { '@odata.nextLink': _ignored, ...rest } = body;
  return { res: { status: first!.status, body: { ...rest, value } }, complete: !link };
}
