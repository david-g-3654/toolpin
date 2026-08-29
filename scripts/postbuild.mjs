// Copy non-TS assets (bundled trust registry) into dist and make the CLI executable.
import { cp, chmod, readFile, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';

await cp('src/registry/data', 'dist/registry/data', { recursive: true });

const cli = 'dist/cli.js';
if (existsSync(cli)) {
  const src = await readFile(cli, 'utf8');
  if (!src.startsWith('#!')) await writeFile(cli, `#!/usr/bin/env node\n${src}`);
  await chmod(cli, 0o755);
}
