import { ACTIVITY_WINDOW_DAYS } from '../graph/queries.js';
import type { AuthMethodView } from './authStrength.js';
import type { RiskDetectionView } from './risk.js';
import { ok, type Section } from './section.js';

// Recent security-info changes, plus the signals that make one worth investigating: Microsoft's own
// "suspicious credential addition" detection, a change made by someone else, or a change close to risky activity.
// None of these confirm compromise – they are persistence signals for an operator to follow up.

export interface CredentialEventView {
  dateTime: string;
  activity: string;
  initiatedBy: string;
  /** False when an admin, app or another account made the change */
  bySelf: boolean;
  source: 'audit' | 'inventory';
  /** Why this change deserves a look; empty when nothing stands out */
  flags: string[];
}

export interface CredentialChangesView {
  events: CredentialEventView[];
  suspiciousDetections: RiskDetectionView[];
}

export interface RiskySignIn {
  createdDateTime: string;
  riskLevel: string;
}

/* eslint-disable @typescript-eslint/no-explicit-any -- Graph payload shapes are mapped field by field below */
type Any = any;

const CORRELATION_MS = 72 * 3_600_000;
const ADDITION = /registered|added|updated|changed default/i;
const ACTIVE_RISK = new Set(['atRisk', 'confirmedCompromised']);

export function buildCredentialChanges(
  audits: Section<Any[]>,
  methods: Section<AuthMethodView[]>,
  risks: Section<RiskDetectionView[]>,
  signIns: RiskySignIn[],
  userId: string,
  now = new Date(),
): Section<CredentialChangesView> {
  if (audits.status !== 'ok' && methods.status !== 'ok') return audits;
  const since = now.getTime() - ACTIVITY_WINDOW_DAYS * 86_400_000;
  const events: CredentialEventView[] = [];

  if (audits.status === 'ok') {
    for (const a of audits.data) {
      const user = a.initiatedBy?.user;
      events.push({
        dateTime: a.activityDateTime,
        activity: String(a.activityDisplayName ?? ''),
        initiatedBy: user?.userPrincipalName || a.initiatedBy?.app?.displayName || 'Unknown',
        bySelf: !!user?.id && String(user.id).toLowerCase() === userId.toLowerCase(),
        source: 'audit',
        flags: [],
      });
    }
  }
  if (methods.status === 'ok') {
    for (const m of methods.data) {
      if (m.kind === 'password' || !m.createdDateTime || Date.parse(m.createdDateTime) < since) continue;
      events.push({
        dateTime: m.createdDateTime,
        activity: `${m.label} registered${m.detail ? ` (${m.detail})` : ''}`,
        initiatedBy: '',
        bySelf: true,
        source: 'inventory',
        flags: [],
      });
    }
  }

  // Risky moments to correlate against: active detections and risky sign-ins
  const riskyMoments = [
    ...(risks.status === 'ok' ? risks.data.filter((r) => ACTIVE_RISK.has(r.state)).map((r) => ({ at: Date.parse(r.detectedDateTime), what: r.typeLabel })) : []),
    ...signIns.filter((s) => s.riskLevel === 'medium' || s.riskLevel === 'high').map((s) => ({ at: Date.parse(s.createdDateTime), what: `${s.riskLevel}-risk sign-in` })),
  ];
  for (const e of events) {
    if (!ADDITION.test(e.activity)) continue;
    if (e.source === 'audit' && !e.bySelf) e.flags.push(`Made by ${e.initiatedBy}`);
    const at = Date.parse(e.dateTime);
    const near = riskyMoments
      .map((r) => ({ ...r, gap: Math.abs(r.at - at) }))
      .filter((r) => r.gap <= CORRELATION_MS)
      .sort((a, b) => a.gap - b.gap)[0];
    if (near) e.flags.push(`Within 72 hours of ${near.what}`);
  }

  events.sort((a, b) => b.dateTime.localeCompare(a.dateTime));
  const suspiciousDetections = risks.status === 'ok' ? risks.data.filter((r) => r.type === 'suspiciousCredentialAddition') : [];
  return ok({ events, suspiciousDetections });
}
