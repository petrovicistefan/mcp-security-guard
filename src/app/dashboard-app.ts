// Dashboard UI, bundled into dist/dashboard.html. Every string from a scanned server reaches the DOM
// through textContent only, never innerHTML, so a malicious description cannot inject markup or script.
import { App, applyDocumentTheme, applyHostStyleVariables } from "@modelcontextprotocol/ext-apps/app-with-deps";
import type { DashboardData, DashboardFinding, DashboardServer } from "../dashboard.js";

type Severity = DashboardFinding["severity"];
const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

const app = new App({ name: "mcp-security dashboard", version: "1.0.0" });
let data: DashboardData | undefined;
let sevFilter: Severity | undefined;
let serverFilter: string | undefined;

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;

function el<K extends keyof HTMLElementTagNameMap>(tag: K, opts: { cls?: string; text?: string; title?: string } = {}, ...children: (Node | null | undefined)[]): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  if (opts.cls) e.className = opts.cls;
  if (opts.text !== undefined) e.textContent = opts.text;
  if (opts.title) e.title = opts.title;
  for (const c of children) if (c) e.append(c);
  return e;
}

function setBusy(busy: boolean, label?: string) {
  for (const id of ["refresh", "full"]) $<HTMLButtonElement>(id).disabled = busy || !data;
  if (busy && label) $("meta").textContent = label;
}

async function load(scan: "config" | "full") {
  setBusy(true, scan === "full" ? "Scanning servers… (each server is started; no tool is called)" : "Reading configuration…");
  try {
    const r = await app.callServerTool({ name: "security_dashboard", arguments: { scan, confirm_launch: scan === "full" } });
    if (r.structuredContent) render(r.structuredContent as unknown as DashboardData);
  } catch (e) {
    $("meta").textContent = `Could not load: ${e instanceof Error ? e.message : String(e)}`;
  } finally {
    setBusy(false);
  }
}

function render(d: DashboardData) {
  data = d;
  $("meta").textContent = `${d.mode === "full" ? "Full scan" : "Configuration only"} · ${new Date(d.generatedAt).toLocaleString()} · v${d.version}`;
  renderChips();
  const notes = $("notes");
  notes.replaceChildren(...d.notes.map((n) => el("li", { text: n })));
  renderServers();
  renderPermissions();
  $("owasp").replaceChildren(...d.owasp.map((o) => el("div", { cls: o.count ? "hit" : "" }, el("b", { text: String(o.count) }), document.createTextNode(` · ${o.id} ${o.name}`))));
  renderFindings();
  setBusy(false);
}

function renderChips() {
  if (!data) return;
  $("chips").replaceChildren(
    ...SEVERITIES.map((s) => {
      const chip = el("div", { cls: `chip${sevFilter === s ? " active" : ""}`, title: `Show only ${s} findings` }, el("b", { cls: `sev-${s}`, text: String(data!.summary[s]) }), el("span", { text: s[0].toUpperCase() + s.slice(1) }));
      chip.onclick = () => {
        sevFilter = sevFilter === s ? undefined : s;
        renderChips();
        renderFindings();
      };
      return chip;
    }),
  );
}

function renderServers() {
  if (!data) return;
  const body = $("servers").querySelector("tbody")!;
  body.replaceChildren(
    ...data.servers.map((s) => {
      const grade = el("span", { cls: `grade g-${s.grade ?? "na"}`, text: s.grade ?? "–" });
      const pin = el("button", { text: s.pinned ? "Re-pin" : "Pin", title: "Record the current definitions so later changes (rug pulls) are detected. Starts the server." });
      pin.disabled = s.scope === "claude-ai" || !!s.error;
      pin.onclick = (ev) => {
        ev.stopPropagation();
        void pinServer(s, pin);
      };
      const row = el(
        "tr",
        { cls: serverFilter === s.key ? "selected" : "", title: s.error ? `Could not connect: ${s.error}` : `Basis: ${s.basis}` },
        el("td", { text: s.name }),
        el("td", { text: s.scope }),
        el("td", { text: s.transport }),
        el("td", {}, grade, document.createTextNode(s.score === null ? "" : ` ${s.score}`)),
        el("td", { cls: "num sev-critical", text: String(s.counts.critical || "") }),
        el("td", { cls: "num sev-high", text: String(s.counts.high || "") }),
        el("td", { cls: "num sev-medium", text: String(s.counts.medium || "") }),
        el("td", { text: s.pinned ? "yes" : "" }),
        el("td", {}, pin),
      );
      row.onclick = () => selectServer(s);
      return row;
    }),
  );
  if (!data.servers.length) body.replaceChildren(el("tr", {}, Object.assign(el("td", { cls: "empty", text: "No MCP servers configured." }), { colSpan: 9 })));
}

function selectServer(s: DashboardServer) {
  serverFilter = serverFilter === s.key ? undefined : s.key;
  renderServers();
  renderFindings();
  if (!data || !serverFilter) return;
  // Let Claude know what the user is looking at, so follow-up questions have context.
  const own = data.findings.filter((f) => f.server === s.name);
  void app
    .updateModelContext({
      structuredContent: { selectedServer: { key: s.key, score: s.score, grade: s.grade, findings: own.map((f) => ({ severity: f.severity, rule: f.rule, title: f.title })) } },
    })
    .catch(() => {});
}

async function pinServer(s: DashboardServer, button: HTMLButtonElement) {
  button.disabled = true;
  button.textContent = "Pinning…";
  try {
    await app.callServerTool({ name: "pin_tools", arguments: { servers: [s.key], confirm_launch: true } });
    await load(data?.mode ?? "config");
  } catch {
    button.textContent = "Failed";
  }
}

function renderPermissions() {
  const show = !!data?.permissions.length;
  $("perms").hidden = !show;
  if (!show) return;
  $("perms-json").textContent = JSON.stringify({ permissions: { ask: data!.permissions } }, null, 2);
  $<HTMLButtonElement>("apply-perms").onclick = () =>
    void app
      .sendMessage({ role: "user", content: [{ type: "text", text: "Use mcp-security's apply_fixes with the permissions fix to add the recommended permission rules. Show me the dry run first." }] })
      .catch(() => {});
}

function card(f: DashboardFinding) {
  const dl = el("dl");
  const add = (k: string, v: Node) => dl.append(el("dt", { text: k }), el("dd", {}, v));
  add("Where", document.createTextNode(f.location));
  const rule = el("span", {}, el("code", { text: f.rule }), ...f.owasp.map((id) => el("span", { cls: "tag", text: id })));
  add("Rule", rule);
  if (f.evidence) add("Evidence", el("code", { cls: "evidence", text: f.evidence }));
  add("Fix", document.createTextNode(f.remediation));
  return el("article", { cls: `finding ${f.severity}` }, el("div", { cls: "head" }, el("span", { cls: `sev sev-${f.severity}`, text: f.severity }), el("span", { cls: "title", text: f.title })), dl);
}

function renderFindings() {
  if (!data) return;
  const server = data.servers.find((s) => s.key === serverFilter);
  const list = data.findings.filter((f) => (!sevFilter || f.severity === sevFilter) && (!server || f.server === server.name));
  $("findings-title").textContent = `Findings${server ? ` · ${server.name}` : ""}${sevFilter ? ` · ${sevFilter}` : ""} (${list.length})`;
  $("findings").replaceChildren(...(list.length ? list.slice(0, 300).map(card) : [el("p", { cls: "empty", text: "No findings for this selection." })]));
}

app.ontoolresult = (result) => {
  if (result.structuredContent) render(result.structuredContent as unknown as DashboardData);
};
app.onhostcontextchanged = (ctx) => {
  if (ctx.theme) applyDocumentTheme(ctx.theme);
  if (ctx.styles?.variables) applyHostStyleVariables(ctx.styles.variables);
};

$("refresh").onclick = () => void load(data?.mode ?? "config");
$("full").onclick = () => void load("full");

void app.connect().then(() => {
  const ctx = app.getHostContext();
  if (ctx?.theme) applyDocumentTheme(ctx.theme);
  if (ctx?.styles?.variables) applyHostStyleVariables(ctx.styles.variables);
});
