// Refreshes src/data/graph-atlas-roles.json from the newest Graph-atlas data release
// (https://github.com/darrenjrobinson/graph-atlas-mcp). Run by hand: `npm run sync:atlas`.
// Pass `--db <path>` to export from a local graph-atlas.db instead of downloading.
//
// The app reads only the committed JSON, so App Service needs no SQLite, GitHub access or MCP runtime.

import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { gunzipSync } from 'node:zlib';

const REPO = 'darrenjrobinson/graph-atlas-mcp';
const ASSET = 'graph-atlas.db.gz';
// Data releases are calendar-tagged (v2026.10.22); semver tags are server releases without a database
const DATA_RELEASE_TAG = /^v\d{4}\.\d{2}\.\d{2}$/;
const OUT = path.resolve(import.meta.dirname, '../src/data/graph-atlas-roles.json');

async function latestDataRelease() {
  for (let page = 1; page <= 10; page++) {
    const res = await fetch(`https://api.github.com/repos/${REPO}/releases?per_page=30&page=${page}`, {
      headers: { accept: 'application/vnd.github+json', 'user-agent': 'ms-user-sync-graph-atlas' },
    });
    if (!res.ok) throw new Error(`GitHub releases API returned HTTP ${res.status}`);
    const releases = await res.json();
    const release = releases.find((r) => !r.draft && DATA_RELEASE_TAG.test(r.tag_name ?? ''));
    if (release) return release;
    if (releases.length < 30) break;
  }
  throw new Error('No calendar-tagged Graph-atlas data release found');
}

async function downloadDb(dir) {
  const release = await latestDataRelease();
  const asset = release.assets.find((a) => a.name === ASSET);
  if (!asset) throw new Error(`${release.tag_name} has no ${ASSET} asset`);
  console.log(`Downloading ${ASSET} from ${release.tag_name}…`);
  const res = await fetch(asset.browser_download_url, { headers: { 'user-agent': 'ms-user-sync-graph-atlas' } });
  if (!res.ok) throw new Error(`Download failed with HTTP ${res.status}`);
  const file = path.join(dir, 'graph-atlas.db');
  await writeFile(file, gunzipSync(Buffer.from(await res.arrayBuffer())));
  return { file, release: release.tag_name };
}

const dbArg = process.argv.indexOf('--db');
const tmp = await mkdtemp(path.join(tmpdir(), 'graph-atlas-'));
try {
  const { file, release } =
    dbArg > 0 ? { file: path.resolve(process.argv[dbArg + 1]), release: 'local' } : await downloadDb(tmp);
  const db = new DatabaseSync(file, { readOnly: true });
  const rows = db
    .prepare('SELECT role_name, template_id, is_privileged, actions, collected_at FROM roles ORDER BY role_name')
    .all();
  db.close();
  if (rows.length === 0) throw new Error('The Graph-atlas roles table is empty');

  const roles = rows.map((r) => ({
    templateId: String(r.template_id).toLowerCase(),
    name: r.role_name,
    isPrivileged: r.is_privileged === 1,
    actions: JSON.parse(r.actions ?? '[]'),
  }));
  const collectedAt = rows.map((r) => r.collected_at).sort().at(-1);
  const out = { source: { repo: REPO, release, collectedAt }, roles };
  await mkdir(path.dirname(OUT), { recursive: true });
  await writeFile(OUT, `${JSON.stringify(out, null, 1)}\n`);
  console.log(`Wrote ${roles.length} roles (${roles.filter((r) => r.isPrivileged).length} privileged) from ${release} to ${path.relative(process.cwd(), OUT)}`);
} finally {
  await rm(tmp, { recursive: true, force: true });
}
