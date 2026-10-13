import { mkdir, readFile, writeFile } from 'node:fs/promises';
const repo = process.env.GH_REPOSITORY || 'petrovicistefan/mcp-security-guard';
const pkg = 'mcp-security-guard';
const token = process.env.GH_TOKEN;
if (!token) throw new Error('GH_TOKEN required');
async function get(url, headers = {}) {
  const response = await fetch(url, { headers: { 'User-Agent': 'mcp-security-guard-metrics', ...headers } });
  if (!response.ok) throw new Error(`${url}: HTTP ${response.status}`);
  return response.json();
}
const ghHeaders = { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' };
const gh = path => get(`https://api.github.com/repos/${repo}${path}`, ghHeaders);
const npm = path => get(`https://api.npmjs.org${path}`);
const [day, week, metadata, repository, issues, pulls, commits, contributors, releases] = await Promise.all([
  npm(`/downloads/point/last-day/${pkg}`),
  npm(`/downloads/point/last-week/${pkg}`),
  npm(`/registry/${pkg}`),
  gh(''),
  gh('/issues?state=open&per_page=100'),
  gh('/pulls?state=open&per_page=100'),
  gh('/commits?per_page=5'),
  gh('/contributors?per_page=100'),
  gh('/releases?per_page=5')
]);
const date = new Date().toISOString().slice(0, 10);
const version = metadata['dist-tags']?.latest ?? null;
const snapshot = {
  date,
  npm: { downloads24h: day.downloads, downloads7d: week.downloads, version, publishedAt: metadata.time?.[version] ?? null },
  github: {
    stars: repository.stargazers_count, forks: repository.forks_count,
    watchers: repository.subscribers_count, openIssues: issues.filter(i => !i.pull_request).length,
    openPullRequests: pulls.length, contributors: contributors.length,
    contributorsMayBeTruncated: contributors.length === 100,
    recentCommits: commits.map(c => ({ sha: c.sha, date: c.commit.committer?.date, message: c.commit.message.split('\n')[0] })),
    latestRelease: releases[0] ? { tag: releases[0].tag_name, publishedAt: releases[0].published_at } : null
  }
};
const path = 'metrics/adoption-history.json';
let history = [];
try { history = JSON.parse(await readFile(path, 'utf8')); } catch (e) { if (e.code !== 'ENOENT') throw e; }
if (!Array.isArray(history)) throw new Error('Invalid metrics history');
history = [...history.filter(item => item.date !== date), snapshot].sort((a,b) => a.date.localeCompare(b.date));
await mkdir('metrics', { recursive: true });
await writeFile(path, JSON.stringify(history, null, 2) + '\n');
const previous = history.at(-2);
const delta = key => previous ? snapshot.github[key] - previous.github[key] : null;
console.log(JSON.stringify({ snapshot, changesSincePrevious: { stars: delta('stars'), forks: delta('forks'), watchers: delta('watchers'), openIssues: delta('openIssues'), openPullRequests: delta('openPullRequests'), npm24h: previous ? snapshot.npm.downloads24h - previous.npm.downloads24h : null, npm7d: previous ? snapshot.npm.downloads7d - previous.npm.downloads7d : null } }, null, 2));
