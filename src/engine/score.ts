import type { Finding, Severity } from '../types.js';
import { SEVERITY_ORDER } from '../types.js';

const WEIGHTS: Record<Severity, number> = { critical: 40, high: 15, medium: 5, low: 1, info: 0 };
const CONFIDENCE_FACTOR = { high: 1, medium: 0.7, low: 0.4 };

export function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
  return counts;
}

/**
 * A single letter, so a badge and a CI summary line can say something useful.
 * Confidence-weighted: five low-confidence heuristics should not outrank one
 * confirmed poisoned description.
 */
export function grade(findings: Finding[]): string {
  // A single credible critical finding is disqualifying on its own: no number of
  // clean files offsets one poisoned tool description.
  if (findings.some((f) => f.severity === 'critical' && f.confidence !== 'low')) return 'F';
  let score = 0;
  for (const f of findings) score += WEIGHTS[f.severity] * CONFIDENCE_FACTOR[f.confidence];
  if (score === 0) return 'A';
  if (score < 5) return 'B';
  if (score < 20) return 'C';
  if (score < 45) return 'D';
  return 'F';
}

export function atLeast(severity: Severity, floor: Severity): boolean {
  return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[floor];
}

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const bySeverity = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
    if (bySeverity !== 0) return bySeverity;
    const byConfidence = { high: 2, medium: 1, low: 0 };
    const c = byConfidence[b.confidence] - byConfidence[a.confidence];
    if (c !== 0) return c;
    return a.location.file.localeCompare(b.location.file) || a.location.line - b.location.line;
  });
}
