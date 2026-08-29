/**
 * Library entry point. Everything the CLI does is available programmatically,
 * so a platform team can run the same rules inside their own tooling.
 */
export * from './types.js';
export { scan, DEFAULT_OPTIONS, VERSION } from './engine/scanner.js';
export { allRules, rulesById, isIgnored } from './rules/index.js';
export { buildLock, readLock, writeLock, detectDrift, type Lockfile } from './engine/lockfile.js';
export { grade, countBySeverity, sortFindings } from './engine/score.js';
export { renderSarif } from './report/sarif.js';
export { renderMarkdown } from './report/markdown.js';
export { renderTerminal, renderCompact } from './report/terminal.js';
export { loadRegistry, evaluateTrust, bundledRegistryPath, packageOf, type Registry } from './registry/trust.js';
export { candidateConfigPaths, parseConfig, projectConfigPaths } from './collect/clientConfig.js';
export { extractTools } from './collect/tools.js';
export { parseFrontmatter } from './collect/skills.js';
export { buildMatcher, readIgnoreFile, type Matcher } from './util/ignore.js';
export { introspectStdio, toolsetFingerprint } from './collect/introspect.js';
