export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export interface Finding {
  severity: Severity;
  rule: string;
  title: string;
  /** Where the issue was found, e.g. `server "github" (project .mcp.json) › args[2]`. */
  location: string;
  /** Sanitized, truncated excerpt. Never contains a full secret. */
  evidence?: string;
  remediation: string;
}

export type ConfigScope = "user" | "local" | "project" | "claude-desktop";

export interface ServerConfig {
  name: string;
  scope: ConfigScope;
  /** Absolute path of the file the entry was read from. */
  source: string;
  type?: string;
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  headers?: Record<string, string>;
}

export interface ToolDefinition {
  name: string;
  title?: string;
  description?: string;
  inputSchema?: unknown;
  annotations?: unknown;
}
