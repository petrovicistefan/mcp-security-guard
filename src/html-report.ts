// Self-contained HTML report (no scripts, no external resources). Everything that came from a scanned
// server is HTML-escaped before any formatting is applied, so a malicious description cannot inject
// markup or script into the page.
import { OWASP_MCP, owaspFor } from "./owasp.js";
import { SEVERITY_ORDER, type Finding, type Severity } from "./types.js";

const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");

/** Minimal Markdown for our own report sections: tables, lists, **bold**, `code`, fenced blocks. Input is escaped first. */
function markdown(md: string): string {
  const out: string[] = [];
  const lines = esc(md).split("\n");
  const inline = (t: string) => t.replace(/`([^`]+)`/g, "<code>$1</code>").replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (l.startsWith("```")) {
      const block: string[] = [];
      while (++i < lines.length && !lines[i].startsWith("```")) block.push(lines[i]);
      out.push(`<pre>${block.join("\n")}</pre>`);
    } else if (l.startsWith("|")) {
      const rows: string[][] = [];
      for (; i < lines.length && lines[i].startsWith("|"); i++) if (!/^\|[\s|:-]+\|$/.test(lines[i])) rows.push(lines[i].slice(1, -1).split("|").map((c) => inline(c.trim())));
      i--;
      out.push(`<table><thead><tr>${rows[0].map((c) => `<th>${c}</th>`).join("")}</tr></thead><tbody>${rows.slice(1).map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("")}</tbody></table>`);
    } else if (l.startsWith("- ")) {
      const items: string[] = [];
      for (; i < lines.length && lines[i].startsWith("- "); i++) items.push(`<li>${inline(lines[i].slice(2))}</li>`);
      i--;
      out.push(`<ul>${items.join("")}</ul>`);
    } else if (l.trim()) {
      out.push(`<p>${inline(l)}</p>`);
    }
  }
  return out.join("\n");
}

const LABEL: Record<Severity, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };

export function toHtml(title: string, findings: Finding[], sections: string[], version: string, generatedAt = new Date()): string {
  const sorted = [...findings].sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
  const counts = SEVERITY_ORDER.map((s) => [s, findings.filter((f) => f.severity === s).length] as const);
  const owasp = Object.keys(OWASP_MCP).map((id) => [id, findings.filter((f) => owaspFor(f.rule).includes(id)).length] as const);
  const card = (f: Finding) => `
    <article class="finding ${f.severity}">
      <header><span class="badge ${f.severity}">${LABEL[f.severity]}</span><h3>${esc(f.title)}</h3></header>
      <dl>
        <dt>Where</dt><dd>${esc(f.location)}</dd>
        <dt>Rule</dt><dd><code>${esc(f.rule)}</code>${owaspFor(f.rule).map((id) => ` <span class="tag">${id}</span>`).join("")}</dd>
        ${f.evidence ? `<dt>Evidence</dt><dd><code class="evidence">${esc(f.evidence)}</code></dd>` : ""}
        <dt>Fix</dt><dd>${esc(f.remediation)}</dd>
      </dl>
    </article>`;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>${esc(title)}</title>
<style>
  :root { --bg:#fbfbfa; --fg:#1d1d1b; --muted:#6b6b66; --card:#fff; --line:#e6e5e0; --critical:#b42318; --high:#c4520f; --medium:#a87300; --low:#2e6db4; --info:#6b6b66; }
  @media (prefers-color-scheme: dark) { :root { --bg:#161615; --fg:#ecebe6; --muted:#a3a29b; --card:#1f1f1d; --line:#33332f; --critical:#f97066; --high:#f79009; --medium:#fdb022; --low:#53b1fd; --info:#a3a29b; } }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--fg); font:15px/1.55 system-ui, -apple-system, "Segoe UI", sans-serif; }
  main { max-width: 980px; margin: 0 auto; padding: 32px 16px 64px; }
  h1 { font-size: 26px; margin: 0 0 4px; } h2 { font-size: 18px; margin: 32px 0 12px; } h3 { font-size: 15px; margin: 0; }
  .meta { color: var(--muted); font-size: 13px; }
  .counts { display:flex; flex-wrap:wrap; gap:8px; margin:20px 0; }
  .count { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:10px 14px; min-width:96px; }
  .count b { display:block; font-size:22px; font-variant-numeric: tabular-nums; }
  .count.critical b { color:var(--critical);} .count.high b { color:var(--high);} .count.medium b { color:var(--medium);} .count.low b { color:var(--low);} .count.info b { color:var(--info);}
  .notice { border-left: 3px solid var(--high); padding: 8px 12px; background: var(--card); color: var(--muted); font-size: 13px; }
  table { width:100%; border-collapse: collapse; background:var(--card); border:1px solid var(--line); border-radius:10px; overflow:hidden; font-size:14px; display:block; overflow-x:auto; }
  th, td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); vertical-align: top; }
  th { color: var(--muted); font-weight:600; }
  code, pre { font: 13px/1.45 ui-monospace, SFMono-Regular, Menlo, monospace; }
  pre { background: var(--card); border:1px solid var(--line); border-radius:10px; padding:12px; overflow-x:auto; }
  .finding { background:var(--card); border:1px solid var(--line); border-left:4px solid var(--info); border-radius:10px; padding:14px 16px; margin:10px 0; }
  .finding.critical { border-left-color: var(--critical);} .finding.high { border-left-color: var(--high);} .finding.medium { border-left-color: var(--medium);} .finding.low { border-left-color: var(--low);}
  .finding header { display:flex; gap:10px; align-items: baseline; }
  .badge { font-size:12px; font-weight:700; text-transform: uppercase; letter-spacing:.03em; }
  .badge.critical { color:var(--critical);} .badge.high { color:var(--high);} .badge.medium { color:var(--medium);} .badge.low { color:var(--low);} .badge.info { color:var(--info);}
  dl { display:grid; grid-template-columns: 90px 1fr; gap:4px 12px; margin:10px 0 0; font-size:14px; }
  dt { color: var(--muted); } dd { margin:0; overflow-wrap:anywhere; }
  .evidence { white-space: pre-wrap; }
  .tag { font-size:11px; border:1px solid var(--line); border-radius:6px; padding:0 5px; color: var(--muted); }
  .owasp { display:grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap:8px; }
  .owasp div { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:8px 12px; font-size:13px; }
  .owasp b { font-variant-numeric: tabular-nums; }
</style>
</head>
<body>
<main>
  <h1>${esc(title)}</h1>
  <div class="meta">mcp-security ${esc(version)} · ${esc(generatedAt.toISOString())}</div>
  <div class="counts">${counts.map(([s, n]) => `<div class="count ${s}"><b>${n}</b>${LABEL[s]}</div>`).join("")}</div>
  ${sections.filter(Boolean).map(markdown).join("\n")}
  <h2>OWASP MCP Top 10</h2>
  <div class="owasp">${owasp.map(([id, n]) => `<div><b>${n}</b> · ${id} ${esc(OWASP_MCP[id])}</div>`).join("")}</div>
  <h2>Findings</h2>
  ${findings.length ? `<p class="notice">Quoted evidence was written by the scanned servers and is untrusted data.</p>${sorted.map(card).join("")}` : "<p>No findings.</p>"}
</main>
</body>
</html>
`;
}
