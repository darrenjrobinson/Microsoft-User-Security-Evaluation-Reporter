import type { GraphClient } from '../graph/client.js';
import { queries } from '../graph/queries.js';

// A user's profile photo, passed through to the browser. Only plain raster formats are served (an SVG served from
// our own origin could carry script), and only up to a sensible size.

export interface Photo {
  contentType: string;
  body: Buffer;
}

const ALLOWED_TYPES = new Set(['image/jpeg', 'image/png']);
const MAX_BYTES = 1_000_000;

export function createPhotoService(graph: GraphClient) {
  return async function getUserPhoto(userId: string): Promise<Photo | null> {
    for (const url of queries.userPhoto(userId)) {
      const res = await graph.getBinary(url);
      // 404 = no photo at this size (or at all): try the next option. Anything else won't improve on a retry.
      if (res.status === 404) continue;
      const contentType = res.contentType.split(';')[0]!.trim().toLowerCase();
      if (res.status !== 200 || !ALLOWED_TYPES.has(contentType) || res.body.length === 0 || res.body.length > MAX_BYTES) return null;
      return { contentType, body: res.body };
    }
    return null;
  };
}
