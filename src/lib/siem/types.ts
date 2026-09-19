export type Severity = "Critical" | "High" | "Medium" | "Low" | "Info";

export type EventType =
  | "SSH Brute Force"
  | "SSH Auth Failure"
  | "Web Fuzzing"
  | "Path Traversal"
  | "SQL Injection"
  | "Firewall Drop"
  | "Port Scan"
  | "Privilege Escalation"
  | "Malware Beacon"
  | "Successful Login"
  | "Unclassified";

export interface SigmaRule {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  mitreId: string;
  mitreName: string;
  tactic: string;
  eventType: EventType;
  status: "active" | "experimental";
  logsource: string;
}

export interface NormalizedEvent {
  id: string;
  timestamp: string; // ISO
  eventType: EventType;
  severity: Severity;
  sourceIp: string;
  destIp?: string | undefined;
  user?: string | undefined;
  asset: string;
  raw: string;
  logSource: "sshd" | "nginx" | "apache" | "ufw" | "syslog" | "kernel" | "unknown";
  rule?: SigmaRule | undefined;
  mitreId?: string | undefined;
  meta: Record<string, string | number | undefined>;
  status: "open" | "contained" | "blocked";
}

export interface ThreatIntel {
  ip: string;
  malicious: boolean;
  confidence: number;
  country: string;
  city: string;
  asn: string;
  tags: string[];
  lastSeen: string;
  firstSeen: string;
  reports: number;
}
