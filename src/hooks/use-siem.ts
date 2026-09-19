import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { toast } from "sonner";
import { correlate, parseBatch } from "@/lib/siem/parser";
import { generateScenario, SAMPLE_LOGS } from "@/lib/siem/simulator";
import type { NormalizedEvent, Severity } from "@/lib/siem/types";

const MAX_BUFFER = 600;
const STREAM_INTERVAL_MS = 3500;

export function useSiem() {
  const [events, setEvents] = useState<NormalizedEvent[]>([]);
  const [streaming, setStreaming] = useState(false);
  const [blockedIps, setBlockedIps] = useState<Set<string>>(() => new Set());
  const [isolatedHosts, setIsolatedHosts] = useState<Set<string>>(() => new Set());
  const [ingestedTotal, setIngestedTotal] = useState(0);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  const ingest = useCallback((newEvents: NormalizedEvent[]) => {
    if (newEvents.length === 0) return 0;
    setIngestedTotal((n) => n + newEvents.length);
    setEvents((prev) => {
      const merged = correlate([...prev, ...newEvents]);
      return merged.slice(-MAX_BUFFER);
    });
    return newEvents.length;
  }, []);

  const ingestRaw = useCallback(
    (text: string) => {
      const parsed = parseBatch(text);
      const n = ingest(parsed);
      if (n === 0) toast.warning("No parseable log lines found in buffer.");
      else {
        const alerts = parsed.filter((e) => e.rule).length;
        toast.success(`Normalized ${n} events`, { description: `${alerts} matched Sigma rules · ${n - alerts} informational` });
      }
      return n;
    },
    [ingest],
  );

  const loadSample = useCallback(() => ingestRaw(SAMPLE_LOGS), [ingestRaw]);

  const purge = useCallback(() => {
    setEvents([]);
    setIngestedTotal(0);
    setBlockedIps(new Set());
    setIsolatedHosts(new Set());
    toast.info("SIEM buffer purged", { description: "All events, containment state and counters reset." });
  }, []);

  const blockIp = useCallback((ip: string) => {
    setBlockedIps((s) => new Set(s).add(ip));
    setEvents((prev) => prev.map((e) => (e.sourceIp === ip ? { ...e, status: "blocked" } : e)));
    toast.success(`Firewall rule pushed`, { description: `DENY inbound from ${ip} on perimeter edge (ufw + cloud SG).` });
  }, []);

  const quarantine = useCallback((host: string) => {
    setIsolatedHosts((s) => new Set(s).add(host));
    setEvents((prev) => prev.map((e) => (e.asset === host && e.status === "open" ? { ...e, status: "contained" } : e)));
    toast.success(`Endpoint quarantined`, { description: `${host} isolated via EDR — only SOC jump-host traffic permitted.` });
  }, []);

  const toggleStream = useCallback(() => setStreaming((s) => !s), []);

  useEffect(() => {
    if (!streaming) {
      if (timer.current) clearInterval(timer.current);
      timer.current = null;
      return;
    }
    ingest(parseBatch(generateScenario().join("\n")));
    timer.current = setInterval(() => {
      ingest(parseBatch(generateScenario().join("\n")));
    }, STREAM_INTERVAL_MS);
    return () => {
      if (timer.current) clearInterval(timer.current);
    };
  }, [streaming, ingest]);

  const metrics = useMemo(() => {
    const alerts = events.filter((e) => e.rule && e.severity !== "Info");
    const bySeverity: Record<Severity, number> = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
    const byType = new Map<string, number>();
    const byMitre = new Map<string, { id: string; name: string; tactic: string; count: number }>();
    for (const e of events) {
      bySeverity[e.severity] += 1;
      if (e.rule) {
        byType.set(e.eventType, (byType.get(e.eventType) ?? 0) + 1);
        const m = byMitre.get(e.rule.mitreId) ?? { id: e.rule.mitreId, name: e.rule.mitreName, tactic: e.rule.tactic, count: 0 };
        m.count += 1;
        byMitre.set(e.rule.mitreId, m);
      }
    }
    return {
      total: ingestedTotal,
      buffered: events.length,
      alerts: alerts.length,
      criticalHigh: bySeverity.Critical + bySeverity.High,
      contained: blockedIps.size + isolatedHosts.size,
      bySeverity,
      byType: [...byType.entries()].map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value),
      ttps: [...byMitre.values()].sort((a, b) => b.count - a.count),
    };
  }, [events, ingestedTotal, blockedIps, isolatedHosts]);

  return { events, streaming, toggleStream, ingestRaw, loadSample, purge, blockIp, quarantine, blockedIps, isolatedHosts, metrics };
}

export type SiemApi = ReturnType<typeof useSiem>;
