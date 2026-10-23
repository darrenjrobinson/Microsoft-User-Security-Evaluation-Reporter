import { z } from 'zod';
import { parsePolicy, type Policy } from './policy.js';

const bool = z
  .string()
  .optional()
  .transform((v) => v !== undefined && ['1', 'true', 'yes'].includes(v.toLowerCase()));

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.coerce.number().int().positive().default(8080),
  // Serve canned data instead of calling Microsoft Graph / HIBP (local dev, tests, demos)
  MOCK_GRAPH: bool,
  // Skip the Easy Auth principal check. Refused when NODE_ENV=production.
  AUTH_DISABLED: bool,
  REQUIRED_ROLE: z.string().min(1).default('MSUser.Operator'),
  HIBP_API_KEY: z.string().optional(),
  HIBP_USER_AGENT: z.string().default('MS-USER-Security-Evaluation-Reporter'),
  APPLICATIONINSIGHTS_CONNECTION_STRING: z.string().optional(),
  // Tenant policy overlays (required-PIM roles, break-glass accounts, thresholds) – see src/policy.ts
  POLICY_JSON: z.string().optional(),
});

export type Config = z.infer<typeof envSchema> & { hibpEnabled: boolean; policy: Policy };

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = envSchema.parse(env);
  if (parsed.AUTH_DISABLED && parsed.NODE_ENV === 'production') {
    throw new Error('AUTH_DISABLED cannot be used when NODE_ENV=production');
  }
  return {
    ...parsed,
    hibpEnabled: parsed.MOCK_GRAPH || Boolean(parsed.HIBP_API_KEY),
    policy: parsePolicy(parsed.POLICY_JSON),
  };
}
