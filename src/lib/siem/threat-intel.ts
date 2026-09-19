import type { ThreatIntel } from "./types";

const KNOWN: Record<string, Omit<ThreatIntel, "ip">> = {
  "185.220.101.47": { malicious: true, confidence: 97, country: "Germany", city: "Frankfurt", asn: "AS205100 F3 Netze e.V.", tags: ["Tor Exit Node", "SSH Brute Force", "Credential Stuffing"], reports: 4821, firstSeen: "2024-11-02", lastSeen: "2026-09-18" },
  "45.155.205.233": { malicious: true, confidence: 94, country: "Russia", city: "Moscow", asn: "AS49505 Selectel", tags: ["Path Traversal", "Web Scanner", "Botnet C2"], reports: 2210, firstSeen: "2025-03-14", lastSeen: "2026-09-19" },
  "103.152.220.11": { malicious: true, confidence: 89, country: "Indonesia", city: "Jakarta", asn: "AS138915 Kaopu Cloud", tags: ["SSH Brute Force", "Mirai Variant"], reports: 1533, firstSeen: "2025-07-22", lastSeen: "2026-09-17" },
  "91.240.118.172": { malicious: true, confidence: 91, country: "Netherlands", city: "Amsterdam", asn: "AS202425 IP Volume inc", tags: ["Port Scan", "Masscan", "Bulletproof Hosting"], reports: 3390, firstSeen: "2024-05-09", lastSeen: "2026-09-19" },
  "196.251.84.19": { malicious: true, confidence: 86, country: "South Africa", city: "Johannesburg", asn: "AS37611 Afrihost", tags: ["SQL Injection", "sqlmap", "Web Fuzzing"], reports: 812, firstSeen: "2026-01-30", lastSeen: "2026-09-16" },
  "23.129.64.130": { malicious: true, confidence: 99, country: "United States", city: "Denver", asn: "AS396507 Emerald Onion", tags: ["Tor Exit Node", "Web Fuzzing", "Log4Shell Probe"], reports: 6104, firstSeen: "2023-09-01", lastSeen: "2026-09-19" },
  "218.92.0.107": { malicious: true, confidence: 98, country: "China", city: "Nanjing", asn: "AS4134 ChinaNet", tags: ["SSH Brute Force", "Password Spraying"], reports: 9871, firstSeen: "2022-02-11", lastSeen: "2026-09-19" },
  "8.8.8.8": { malicious: false, confidence: 2, country: "United States", city: "Mountain View", asn: "AS15169 Google LLC", tags: ["Public DNS", "Allowlisted"], reports: 0, firstSeen: "2009-12-01", lastSeen: "2026-09-19" },
  "1.1.1.1": { malicious: false, confidence: 1, country: "Australia", city: "Sydney", asn: "AS13335 Cloudflare", tags: ["Public DNS", "Allowlisted"], reports: 0, firstSeen: "2018-04-01", lastSeen: "2026-09-19" },
};

export const MALICIOUS_IPS = Object.keys(KNOWN).filter((ip) => KNOWN[ip]?.malicious);

const COUNTRIES = [
  ["Brazil", "São Paulo", "AS28573 Claro"],
  ["India", "Mumbai", "AS55836 Reliance Jio"],
  ["Vietnam", "Hanoi", "AS45899 VNPT"],
  ["France", "Paris", "AS16276 OVH SAS"],
  ["United States", "Ashburn", "AS14618 Amazon"],
  ["Ukraine", "Kyiv", "AS6849 Ukrtelecom"],
];

function hash(s: string) {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 16777619);
  return Math.abs(h >>> 0);
}

export function isPrivateIp(ip: string) {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)/.test(ip);
}

export function lookupIp(ip: string): ThreatIntel {
  const known = KNOWN[ip];
  if (known) return { ip, ...known };
  if (isPrivateIp(ip)) {
    return { ip, malicious: false, confidence: 0, country: "Internal", city: "RFC1918", asn: "Private Network", tags: ["Internal Asset"], reports: 0, firstSeen: "-", lastSeen: "-" };
  }
  const h = hash(ip);
  const c = COUNTRIES[h % COUNTRIES.length] ?? ["Unknown", "Unknown", "AS0 Unknown"];
  const suspicious = h % 5 === 0;
  return {
    ip,
    malicious: suspicious,
    confidence: suspicious ? 55 + (h % 30) : h % 15,
    country: c[0] ?? "Unknown",
    city: c[1] ?? "Unknown",
    asn: c[2] ?? "Unknown",
    tags: suspicious ? ["Suspicious Activity", "Low Reputation"] : ["No Known Abuse"],
    reports: suspicious ? 20 + (h % 200) : 0,
    firstSeen: suspicious ? "2026-06-12" : "-",
    lastSeen: suspicious ? "2026-09-15" : "-",
  };
}

export function isValidIp(ip: string) {
  return /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.test(ip) && ip.split(".").every((o) => Number(o) <= 255);
}
