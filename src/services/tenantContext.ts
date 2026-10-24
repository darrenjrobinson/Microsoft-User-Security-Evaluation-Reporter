import type { GraphClient } from '../graph/client.js';
import { queries } from '../graph/queries.js';
import { isOk, ok, unavailableFrom, type Section } from './section.js';

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
    let value: Section<TenantContextView>;
    if (!isOk(methodsRes) && !isOk(defaultsRes)) {
      value = unavailableFrom(methodsRes);
    } else {
      const configs: Any[] = isOk(methodsRes) ? ((methodsRes!.body as Any)?.authenticationMethodConfigurations ?? []) : [];
      const label = (c: Any) => METHOD_POLICY_LABELS[c.id] ?? String(c.id);
      value = ok({
        methodsEnabled: configs.filter((c) => c.state === 'enabled').map(label),
        methodsDisabled: configs.filter((c) => c.state !== 'enabled').map(label),
        securityDefaults: isOk(defaultsRes) ? !!(defaultsRes!.body as Any)?.isEnabled : null,
      });
    }
    // Don't pin a transient failure for the whole TTL
    if (value.status === 'ok') cached = { at: Date.now(), value };
    return value;
  };
}
