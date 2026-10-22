import './telemetry.js';
import { createApp } from './app.js';
import { loadConfig } from './config.js';

const config = loadConfig();
const app = createApp(config);

const server = app.listen(config.PORT, () => {
  const mode = [config.MOCK_GRAPH && 'mock Graph', config.AUTH_DISABLED && 'auth disabled'].filter(Boolean).join(', ');
  console.log(`MS USER listening on http://localhost:${config.PORT}${mode ? ` (${mode})` : ''}`);
});

for (const signal of ['SIGTERM', 'SIGINT'] as const) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
