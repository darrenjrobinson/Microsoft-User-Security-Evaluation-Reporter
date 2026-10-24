import type { GraphClient } from '../graph/client.js';
import { queries } from '../graph/queries.js';
import { ok, unavailableFrom, type Section } from './section.js';

// Tenant-wide settings that explain a user's posture (e.g. "not passwordless because passkeys are disabled").
// Lightweight context, not a tenant assessment. Same for every user, so it's cached.

export interface TenantContextView {
  methodsEnabled: string[];
  methodsDisabled: string[];
  securityDefaults: boolean | null;
}

/* eslint-disable @typescript-eslint/no-explicit-any -- Graph payload shapes are mapped field by field below */
type Any = any;

export const METHOD_POLICY_LABELS: Record<string, string> = {
  Fido2: 'Passkeys (FIDO2)',
  MicrosoftAuthenticator: 'Microsoft Authenticator',
  Sms: 'SMS',
  Voice: 'Voice call',
  TemporaryAccessPass: 'Temporary Access Pass',
  Email: 'Email OTP',
  X509Certificate: 'Certificate-based authentication',
  SoftwareOath: 'Third-party software OATH',
  HardwareOath: 'Hardware OATH tokens',
  QRCodePin: 'QR code + PIN',
};

const TTL_MS = 15 * 60_000;

export function createTenantContext(graph: GraphClient) {
  let cached: { at: number; value: Section<TenantContextView> } | undefined;

  return async function getTenantContext(): Promise<Section<TenantContextView>> {
    if (cached && Date.now() - cached.at < TTL_MS) return cached.value;
    const responses = await graph.batch(queries.tenantPolicies());
    const methodsRes = responses.get('authMethodsPolicy');
    const defaultsRes = responses.get('securityDefaults');
    // Only use what Graph actually returned: a missing property is unknown, never "disabled"
    const configs: unknown = (methodsRes?.status === 200 ? (methodsRes.body as Any) : null)?.authenticationMethodConfigurations;
    const isEnabled: unknown = (defaultsRes?.status === 200 ? (defaultsRes.body as Any) : null)?.isEnabled;
    let value: Section<TenantContextView>;
    if (!Array.isArray(configs) && typeof isEnabled !== 'boolean') {
      value = unavailableFrom(methodsRes);
    } else {
      const list: Any[] = Array.isArray(configs) ? configs : [];
      const label = (c: Any) => METHOD_POLICY_LABELS[c.id] ?? String(c.id);
      value = ok({
        methodsEnabled: list.filter((c) => c.state === 'enabled').map(label),
        methodsDisabled: list.filter((c) => c.state !== 'enabled').map(label),
        securityDefaults: typeof isEnabled === 'boolean' ? isEnabled : null,
      });
    }
    // Don't pin a transient failure for the whole TTL
    if (value.status === 'ok') cached = { at: Date.now(), value };
    return value;
  };
}
