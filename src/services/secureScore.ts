import type { GraphClient } from '../graph/client.js';
import { queries } from '../graph/queries.js';

interface GraphSecureScore {
  createdDateTime: string;
  currentScore: number;
  maxScore: number;
  averageComparativeScores?: { basis: string; averageScore: number }[];
}

export interface SecureScoreView {
  currentScore: number;
  maxScore: number;
  percentage: number;
  /** 0–5, matching the original star summary */
  stars: number;
  allTenantsAveragePercentage: number | null;
  createdDateTime: string;
}

const CACHE_MS = 60 * 60 * 1000; // Secure Score is calculated once a day

export function toSecureScoreView(score: GraphSecureScore): SecureScoreView {
  const pct = (n: number) => (score.maxScore > 0 ? Math.round((n / score.maxScore) * 100) : 0);
  const percentage = pct(score.currentScore);
  const allTenants = score.averageComparativeScores?.find((s) => s.basis === 'AllTenants');
  return {
    currentScore: Math.round(score.currentScore * 100) / 100,
    maxScore: score.maxScore,
    percentage,
    stars: Math.min(5, Math.round(percentage / 20)),
    allTenantsAveragePercentage: allTenants ? pct(allTenants.averageScore) : null,
    createdDateTime: score.createdDateTime,
  };
}

export function createSecureScoreService(graph: GraphClient) {
  let cached: { at: number; value: SecureScoreView | null } | undefined;

  return async function getSecureScore(): Promise<SecureScoreView | null> {
    if (cached && Date.now() - cached.at < CACHE_MS) return cached.value;
    const res = await graph.get<{ value: GraphSecureScore[] }>(queries.secureScore());
    const latest = res.body.value[0];
    const value = latest ? toSecureScoreView(latest) : null;
    cached = { at: Date.now(), value };
    return value;
  };
}
