import type { GraphClient } from '../graph/client.js';
import { queries } from '../graph/queries.js';

export interface GraphRiskDetection {
  id: string;
  riskEventType: string;
  riskLevel: string;
  riskState: string;
  riskDetail?: string;
  detectedDateTime: string;
  userId: string;
  userDisplayName?: string;
  userPrincipalName?: string;
  ipAddress?: string;
  location?: { city?: string; state?: string; countryOrRegion?: string };
  source?: string;
}

export interface RiskDetectionView {
  id: string;
  type: string;
  typeLabel: string;
  level: string;
  state: string;
  detectedDateTime: string;
  userId: string;
  userDisplayName: string;
  userPrincipalName: string;
  ipAddress: string;
  location: string;
}

// Friendly names for the common Entra ID Protection detections
const RISK_LABELS: Record<string, string> = {
  anonymizedIPAddress: 'Anonymous IP address',
  leakedCredentials: 'Leaked credentials',
  impossibleTravel: 'Atypical travel',
  unlikelyTravel: 'Atypical travel',
  maliciousIPAddress: 'Malicious IP address',
  malwareInfectedIPAddress: 'Malware linked IP address',
  unfamiliarFeatures: 'Unfamiliar sign-in properties',
  passwordSpray: 'Password spray',
  investigationsThreatIntelligence: 'Microsoft Entra threat intelligence',
  suspiciousBrowser: 'Suspicious browser',
  suspiciousInboxForwarding: 'Suspicious inbox forwarding',
  mcasSuspiciousInboxManipulationRules: 'Suspicious inbox manipulation rules',
  newCountry: 'New country',
  anomalousToken: 'Anomalous token',
  tokenIssuerAnomaly: 'Token issuer anomaly',
  adminConfirmedUserCompromised: 'Admin confirmed user compromised',
  attackerinTheMiddle: 'Attacker in the middle',
  suspiciousAPITraffic: 'Suspicious API traffic',
};

export const riskLabel = (type: string) => RISK_LABELS[type] ?? type.replace(/([a-z])([A-Z])/g, '$1 $2');

export function toRiskView(d: GraphRiskDetection): RiskDetectionView {
  const loc = d.location;
  return {
    id: d.id,
    type: d.riskEventType,
    typeLabel: riskLabel(d.riskEventType),
    level: d.riskLevel,
    state: d.riskState,
    detectedDateTime: d.detectedDateTime,
    userId: d.userId,
    userDisplayName: d.userDisplayName ?? '',
    userPrincipalName: d.userPrincipalName ?? '',
    ipAddress: d.ipAddress ?? '',
    location: [loc?.city, loc?.state, loc?.countryOrRegion].filter(Boolean).join(', '),
  };
}

export const byNewest = (a: { detectedDateTime: string }, b: { detectedDateTime: string }) =>
  b.detectedDateTime.localeCompare(a.detectedDateTime);

export function createRiskService(graph: GraphClient) {
  /** The five most recent active (atRisk) detections, as shown on page load in the original app. */
  return async function getRecentRisks(limit = 5): Promise<RiskDetectionView[]> {
    const res = await graph.get<{ value: GraphRiskDetection[] }>(queries.recentRiskDetections());
    return [...res.body.value].sort(byNewest).slice(0, limit).map(toRiskView);
  };
}

