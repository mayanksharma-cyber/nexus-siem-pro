import { SIGMA_RULES, ruleByType } from "./sigma-rules";
import type { EventType, NormalizedEvent, Severity, SigmaRule } from "./types";

let counter = 0;
export function nextId() {
  counter += 1;
  return `EVT-${Date.now().toString(36).toUpperCase()}-${counter.toString(36).toUpperCase().padStart(3, "0")}`;
}

const IP_RE = /\b(\d{1,3}(?:\.\d{1,3}){3})\b/;
const MONTHS: Record<string, number> = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };

function parseSyslogTs(line: string): string | undefined {
  const m = line.match(/^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})/);
  if (!m) return undefined;
  const d = new Date();
  d.setMonth(MONTHS[m[1] ?? ""] ?? d.getMonth(), Number(m[2]));
  d.setHours(Number(m[3]), Number(m[4]), Number(m[5]), 0);
  return d.toISOString();
}

function parseApacheTs(line: string): string | undefined {
  const m = line.match(/\[(\d{2})\/([A-Z][a-z]{2})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})/);
  if (!m) return undefined;
  const d = new Date(Number(m[3]), MONTHS[m[2] ?? ""] ?? 0, Number(m[1]), Number(m[4]), Number(m[5]), Number(m[6]));
  return d.toISOString();
}

function classifyWeb(uri: string, ua: string, status: string): EventType {
  const u = decodeURIComponent(uri.replace(/%25/g, "%")).toLowerCase();
  if (/\.\.\/|\.\.\\|\/etc\/passwd|\/proc\/self|boot\.ini|%2e%2e/.test(u)) return "Path Traversal";
  if (/union\s+select|or\s+1=1|'--|sleep\(|benchmark\(|information_schema|;\s*drop/.test(u)) return "SQL Injection";
  if (/nikto|sqlmap|gobuster|ffuf|dirbuster|nuclei|masscan|zgrab|python-requests|curl\//i.test(ua)) return "Web Fuzzing";
  if (/\/(wp-admin|wp-login|\.env|\.git|phpmyadmin|admin|config|backup|\.aws|actuator)/.test(u) && /^(40[0-4])$/.test(status)) return "Web Fuzzing";
  return "Unclassified";
}

function build(partial: Omit<NormalizedEvent, "id" | "severity" | "rule" | "mitreId" | "status"> & { rule?: SigmaRule | undefined }): NormalizedEvent {
  const rule = partial.rule ?? ruleByType(partial.eventType);
  const severity: Severity = rule ? rule.severity : "Info";
  return { id: nextId(), status: "open", ...partial, rule, mitreId: rule?.mitreId, severity };
}

export function parseLine(line: string): NormalizedEvent | null {
  const raw = line.trim();
  if (!raw) return null;
  const now = new Date().toISOString();

  // --- sshd ---
  if (/sshd\[\d+\]/.test(raw)) {
    const ts = parseSyslogTs(raw) ?? now;
    const host = raw.match(/^\w{3}\s+\d+\s+[\d:]+\s+(\S+)/)?.[1] ?? "unknown-host";
    const ip = raw.match(IP_RE)?.[1] ?? "0.0.0.0";
    const port = raw.match(/port\s+(\d+)/)?.[1];
    let m: RegExpMatchArray | null;
    if ((m = raw.match(/Failed password for (?:invalid user )?(\S+) from/))) {
      const invalid = /invalid user/.test(raw);
      return build({ timestamp: ts, eventType: "SSH Auth Failure", sourceIp: ip, user: m[1], asset: host, raw, logSource: "sshd", meta: { port, invalidUser: invalid ? "yes" : "no", method: "password" } });
    }
    if ((m = raw.match(/Accepted (\S+) for (\S+) from/))) {
      return build({ timestamp: ts, eventType: "Successful Login", sourceIp: ip, user: m[2], asset: host, raw, logSource: "sshd", meta: { port, method: m[1] } });
    }
    if (/Invalid user|Connection closed by authenticating user|maximum authentication attempts/.test(raw)) {
      const u = raw.match(/(?:Invalid user|authenticating user) (\S+)/)?.[1];
      return build({ timestamp: ts, eventType: "SSH Auth Failure", sourceIp: ip, user: u, asset: host, raw, logSource: "sshd", meta: { port, reason: "invalid-or-closed" } });
    }
    return build({ timestamp: ts, eventType: "Unclassified", sourceIp: ip, asset: host, raw, logSource: "sshd", meta: {} });
  }

  // --- sudo ---
  if (/sudo(\[\d+\])?:/.test(raw)) {
    const ts = parseSyslogTs(raw) ?? now;
    const host = raw.match(/^\w{3}\s+\d+\s+[\d:]+\s+(\S+)/)?.[1] ?? "unknown-host";
    const user = raw.match(/sudo(?:\[\d+\])?:\s+(\S+)/)?.[1];
    const cmd = raw.match(/COMMAND=(.*)$/)?.[1];
    const esc = /COMMAND=.*(\/bin\/(ba)?sh|su\b|passwd|visudo)|authentication failure|NOT in sudoers/.test(raw);
    return build({ timestamp: ts, eventType: esc ? "Privilege Escalation" : "Unclassified", sourceIp: "127.0.0.1", user, asset: host, raw, logSource: "syslog", meta: { command: cmd } });
  }

  // --- UFW / iptables ---
  if (/\[UFW (BLOCK|AUDIT|ALLOW)\]|kernel:.*(DROP|BLOCK)/.test(raw)) {
    const ts = parseSyslogTs(raw) ?? now;
    const host = raw.match(/^\w{3}\s+\d+\s+[\d:]+\s+(\S+)/)?.[1] ?? "fw-edge";
    const src = raw.match(/SRC=(\S+)/)?.[1] ?? "0.0.0.0";
    const dst = raw.match(/DST=(\S+)/)?.[1];
    const dpt = raw.match(/DPT=(\d+)/)?.[1];
    const proto = raw.match(/PROTO=(\S+)/)?.[1];
    const iface = raw.match(/IN=(\S+)/)?.[1];
    return build({ timestamp: ts, eventType: "Firewall Drop", sourceIp: src, destIp: dst, asset: host, raw, logSource: "ufw", meta: { dstPort: dpt, proto, iface } });
  }

  // --- Nginx / Apache combined log ---
  const web = raw.match(/^(\S+) \S+ (\S+) \[[^\]]+\] "(\S+) (\S+)[^"]*" (\d{3}) (\S+)(?: "([^"]*)" "([^"]*)")?/);
  if (web) {
    const [, ip, authUser, method, uri, status, bytes, referer, ua] = web;
    const ts = parseApacheTs(raw) ?? now;
    const type = classifyWeb(uri ?? "", ua ?? "", status ?? "");
    return build({
      timestamp: ts,
      eventType: type,
      sourceIp: ip ?? "0.0.0.0",
      user: authUser && authUser !== "-" ? authUser : undefined,
      asset: "web-frontend-01",
      raw,
      logSource: /nginx/i.test(ua ?? "") ? "nginx" : "nginx",
      meta: { method, uri, status, bytes, referer, userAgent: ua },
    });
  }

  // --- Generic: try IP ---
  const ip = raw.match(IP_RE)?.[1] ?? "0.0.0.0";
  const ts = parseSyslogTs(raw) ?? now;
  return build({ timestamp: ts, eventType: "Unclassified", sourceIp: ip, asset: "syslog-collector", raw, logSource: "unknown", meta: {} });
}

/**
 * Correlation pass: promotes repeated SSH failures to Brute Force, repeated
 * firewall drops on distinct ports to Port Scan, and successful logins after
 * brute force to Critical.
 */
export function correlate(events: NormalizedEvent[]): NormalizedEvent[] {
  const sshFails = new Map<string, number>();
  const fwPorts = new Map<string, Set<string>>();
  for (const e of events) {
    if (e.eventType === "SSH Auth Failure" || e.eventType === "SSH Brute Force") sshFails.set(e.sourceIp, (sshFails.get(e.sourceIp) ?? 0) + 1);
    if (e.eventType === "Firewall Drop" || e.eventType === "Port Scan") {
      const s = fwPorts.get(e.sourceIp) ?? new Set<string>();
      s.add(String(e.meta["dstPort"] ?? ""));
      fwPorts.set(e.sourceIp, s);
    }
  }
  const bruteSources = new Set([...sshFails.entries()].filter(([, n]) => n >= 3).map(([ip]) => ip));
  const scanSources = new Set([...fwPorts.entries()].filter(([, s]) => s.size >= 4).map(([ip]) => ip));

  return events.map((e) => {
    if (e.eventType === "SSH Auth Failure" && bruteSources.has(e.sourceIp)) {
      const rule = ruleByType("SSH Brute Force");
      return { ...e, eventType: "SSH Brute Force", rule, mitreId: rule?.mitreId, severity: rule?.severity ?? e.severity, meta: { ...e.meta, failedAttempts: sshFails.get(e.sourceIp) } };
    }
    if (e.eventType === "Firewall Drop" && scanSources.has(e.sourceIp)) {
      const rule = ruleByType("Port Scan");
      return { ...e, eventType: "Port Scan", rule, mitreId: rule?.mitreId, severity: rule?.severity ?? e.severity, meta: { ...e.meta, distinctPorts: fwPorts.get(e.sourceIp)?.size } };
    }
    if (e.eventType === "Successful Login") {
      if (bruteSources.has(e.sourceIp)) {
        const rule = SIGMA_RULES.find((r) => r.id === "SIG-010");
        return { ...e, rule, mitreId: rule?.mitreId, severity: "Critical" };
      }
      return { ...e, rule: undefined, mitreId: undefined, severity: "Info" };
    }
    return e;
  });
}

export function parseBatch(text: string): NormalizedEvent[] {
  const parsed = text
    .split(/\r?\n/)
    .map(parseLine)
    .filter((e): e is NormalizedEvent => e !== null);
  return correlate(parsed);
}
