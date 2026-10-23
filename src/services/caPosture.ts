// Conditional Access interpretation for recent sign-ins: was MFA actually enforced, and is the user repeatedly
// hitting policy failures? Deliberately a posture summary, not a CA troubleshooting tool.

export interface CaPostureView {
  total: number;
  mfaSatisfied: number;
  singleFactor: number;
  /** Successful single-factor sign-ins that no Conditional Access policy applied to */
  unprotected: number;
  caFailures: number;
  blockedByPolicy: number;
  deviceNotCompliant: number;
  /** Sign-in evidence came from the beta endpoint (more rows) or the v1.0 panel query */
  source: 'beta' | 'v1.0';
}

/* eslint-disable @typescript-eslint/no-explicit-any -- Graph payload shapes are mapped field by field below */
type Any = any;

// AADSTS 53003: blocked by Conditional Access; 53000/53001/530003: device must be compliant / joined
const BLOCKED = new Set([53003]);
const DEVICE = new Set([53000, 53001, 530003]);

export function buildCaPosture(signIns: Any[], source: 'beta' | 'v1.0'): CaPostureView {
  const v: CaPostureView = { total: 0, mfaSatisfied: 0, singleFactor: 0, unprotected: 0, caFailures: 0, blockedByPolicy: 0, deviceNotCompliant: 0, source };
  for (const s of signIns) {
    if (s.isInteractive === false) continue;
    v.total++;
    const code = Number(s.status?.errorCode ?? 0);
    const success = code === 0;
    const mfa = s.authenticationRequirement === 'multiFactorAuthentication';
    if (success && mfa) v.mfaSatisfied++;
    if (success && !mfa) {
      v.singleFactor++;
      if (s.conditionalAccessStatus === 'notApplied') v.unprotected++;
    }
    if (s.conditionalAccessStatus === 'failure') v.caFailures++;
    if (BLOCKED.has(code)) v.blockedByPolicy++;
    if (DEVICE.has(code)) v.deviceNotCompliant++;
  }
  return v;
}
