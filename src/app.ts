import compression from 'compression';
import express, { type NextFunction, type Request, type Response } from 'express';
import helmet from 'helmet';
import path from 'node:path';
import { requireOperator } from './auth.js';
import type { Config } from './config.js';
import { GraphError, HttpGraphClient, type GraphClient } from './graph/client.js';
import { mockPolicy } from './mock/fixtures.js';
import { MockGraphClient, mockHibpFetch } from './mock/mockGraph.js';
import { parsePolicy } from './policy.js';
import { apiRouter } from './routes/api.js';
import { createHibpService, type HibpLookup } from './services/hibp.js';
import { createProfileService } from './services/profile.js';
import { createRiskService } from './services/risk.js';
import { createSecureScoreService } from './services/secureScore.js';
import { unavailableFrom } from './services/section.js';
import { createUserSearchService } from './services/users.js';

// src/ and dist/ both sit directly under the project root
const ROOT = path.resolve(import.meta.dirname, '..');

export interface AppDeps {
  graph?: GraphClient;
  hibp?: HibpLookup;
}

export function createApp(config: Config, deps: AppDeps = {}) {
  const graph = deps.graph ?? (config.MOCK_GRAPH ? new MockGraphClient() : new HttpGraphClient());
  // The demo tenant has a break-glass account and sensitive groups to show off
  const policy = config.MOCK_GRAPH && !config.POLICY_JSON ? parsePolicy(JSON.stringify(mockPolicy)) : config.policy;
  const hibp =
    deps.hibp ??
    createHibpService({
      apiKey: config.MOCK_GRAPH ? 'mock' : config.HIBP_API_KEY,
      userAgent: config.HIBP_USER_AGENT,
      fetchImpl: config.MOCK_GRAPH ? mockHibpFetch : undefined,
    });

  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', true);

  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'"],
          imgSrc: ["'self'", 'data:'],
          fontSrc: ["'self'"],
          connectSrc: ["'self'"],
          frameAncestors: ["'none'"],
          formAction: ["'self'"],
          upgradeInsecureRequests: config.NODE_ENV === 'production' ? [] : null,
        },
      },
      crossOriginEmbedderPolicy: false,
    }),
  );
  app.use(compression());

  app.get('/healthz', (_req, res) => {
    res.set('Cache-Control', 'no-store').json({ status: 'ok' });
  });

  const staticOpts = { maxAge: config.NODE_ENV === 'production' ? '1h' : 0 };
  app.use('/vendor/bootstrap', express.static(path.join(ROOT, 'node_modules/bootstrap/dist'), staticOpts));
  app.use('/vendor/bootstrap-icons', express.static(path.join(ROOT, 'node_modules/bootstrap-icons/font'), staticOpts));
  // Our own HTML/CSS/JS change with every deploy and aren't fingerprinted, so make browsers revalidate them
  app.use(
    express.static(path.join(ROOT, 'public'), {
      ...staticOpts,
      setHeaders: (res, filePath) => {
        if (/\.(html|css|js)$/.test(filePath)) res.setHeader('Cache-Control', 'no-cache');
      },
    }),
  );

  app.use(
    '/api',
    requireOperator(config.REQUIRED_ROLE, config.AUTH_DISABLED),
    apiRouter(
      {
        getSecureScore: createSecureScoreService(graph),
        getRecentRisks: createRiskService(graph),
        searchUsers: createUserSearchService(graph),
        getUserProfile: createProfileService(graph, hibp, policy),
      },
      { hibpEnabled: config.hibpEnabled, mock: config.MOCK_GRAPH },
    ),
  );

  // Express recognises error handlers by their 4-argument signature
  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    if (err instanceof GraphError) {
      const why = unavailableFrom({ status: err.status, body: { error: { code: err.code, message: err.message } } });
      res.status(502).json({ error: why.reason, message: why.message });
      return;
    }
    console.error(err);
    res.status(500).json({ error: 'internal', message: 'Something went wrong. Check Application Insights for details.' });
  });

  return app;
}
