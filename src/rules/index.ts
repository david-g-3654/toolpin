import type { Rule } from '../types.js';
import { injectionRules } from './injection.js';
import { codeRules } from './code.js';
import { structuralRules } from './structural.js';

/** Every rule the scanner knows about, in a stable order. */
export const allRules: Rule[] = [...injectionRules, ...codeRules, ...structuralRules];

export function rulesById(): Map<string, Rule> {
  return new Map(allRules.map((r) => [r.id, r]));
}

/** Resolve an --ignore token, which may be a rule id, a prefix, or a category. */
export function isIgnored(rule: Rule, ignore: string[]): boolean {
  return ignore.some((token) => {
    const t = token.trim().toLowerCase();
    if (!t) return false;
    return rule.id.toLowerCase() === t || rule.id.toLowerCase().startsWith(t) || rule.category === t;
  });
}

export { injectionRules, codeRules, structuralRules };
