import { discoverServers, type DiscoveryResult } from "./config.js";
import { auditDuplicates, auditServerConfig } from "./rules/config-rules.js";
import type { Finding } from "./types.js";

export interface ConfigAudit extends DiscoveryResult {
  findings: Finding[];
}

/** Static config audit shared by the MCP tool and the CLI. `projectOnly` keeps only the repo's .mcp.json, for deterministic CI runs. */
export function auditConfig(projectDir: string, opts: { projectOnly?: boolean } = {}): ConfigAudit {
  const discovered = discoverServers(projectDir);
  const servers = opts.projectOnly ? discovered.servers.filter((s) => s.scope === "project") : discovered.servers;
  return { ...discovered, servers, findings: [...servers.flatMap(auditServerConfig), ...auditDuplicates(servers)] };
}
