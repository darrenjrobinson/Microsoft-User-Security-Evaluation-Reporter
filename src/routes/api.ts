import { Router, type NextFunction, type Request, type Response } from 'express';
import { z } from 'zod';
import { isObjectId } from '../graph/queries.js';
import { UserNotFoundError, type createProfileService } from '../services/profile.js';
import type { createPhotoService } from '../services/photo.js';
import type { createRiskService } from '../services/risk.js';
import type { createSecureScoreService } from '../services/secureScore.js';
import type { createUserSearchService } from '../services/users.js';

export interface ApiServices {
  getSecureScore: ReturnType<typeof createSecureScoreService>;
  getRecentRisks: ReturnType<typeof createRiskService>;
  searchUsers: ReturnType<typeof createUserSearchService>;
  getUserProfile: ReturnType<typeof createProfileService>;
  getUserPhoto: ReturnType<typeof createPhotoService>;
}

const searchQuery = z.object({
  q: z
    .string()
    .trim()
    .min(2, 'Enter at least 2 characters')
    .max(64, 'Search text is too long')
    .regex(/^[\p{L}\p{N} .@_'’-]+$/u, 'Search text contains unsupported characters'),
});

type Handler = (req: Request, res: Response) => Promise<unknown>;
const wrap = (fn: Handler) => (req: Request, res: Response, next: NextFunction) => fn(req, res).catch(next);

export function apiRouter(services: ApiServices, info: { hibpEnabled: boolean; mock: boolean }): Router {
  const router = Router();

  router.use((_req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
  });

  router.get('/me', (req, res) => {
    res.json({ name: req.operator?.name ?? 'Operator', hibpEnabled: info.hibpEnabled, mock: info.mock });
  });

  router.get(
    '/securescore',
    wrap(async (_req, res) => res.json({ data: await services.getSecureScore() })),
  );

  router.get(
    '/risk/recent',
    wrap(async (_req, res) => res.json({ data: await services.getRecentRisks() })),
  );

  router.get(
    '/users',
    wrap(async (req, res) => {
      const parsed = searchQuery.safeParse(req.query);
      if (!parsed.success) {
        return res.status(400).json({ error: 'badRequest', message: parsed.error.issues[0]?.message ?? 'Invalid search' });
      }
      return res.json({ data: await services.searchUsers(parsed.data.q) });
    }),
  );

  router.get(
    '/users/:id/profile',
    wrap(async (req, res) => {
      const id = String(req.params.id);
      if (!isObjectId(id)) return res.status(400).json({ error: 'badRequest', message: 'A user object id is required' });
      try {
        return res.json(await services.getUserProfile(id));
      } catch (err) {
        if (err instanceof UserNotFoundError) return res.status(404).json({ error: 'notFound', message: 'User not found' });
        throw err;
      }
    }),
  );

  router.get(
    '/users/:id/photo',
    wrap(async (req, res) => {
      const id = String(req.params.id);
      if (!isObjectId(id)) return res.status(400).json({ error: 'badRequest', message: 'A user object id is required' });
      const photo = await services.getUserPhoto(id);
      // No photo is normal – the UI shows initials instead
      if (!photo) return res.status(404).json({ error: 'notFound', message: 'No photo' });
      // Photos rarely change; let this operator's browser reuse it for an hour, but never a shared cache
      return res.set({ 'Cache-Control': 'private, max-age=3600', 'Content-Type': photo.contentType }).send(photo.body);
    }),
  );

  router.use((_req, res) => res.status(404).json({ error: 'notFound', message: 'Unknown API route' }));

  return router;
}
