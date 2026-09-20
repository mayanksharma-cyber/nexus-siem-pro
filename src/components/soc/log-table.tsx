import { useMemo, useState } from "react";
import { Download, FileSpreadsheet, Microscope, Search, ShieldBan, ShieldCheck, Terminal } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { SeverityBadge } from "./severity-badge";
import type { NormalizedEvent, Severity } from "@/lib/siem/types";
import type { SiemApi } from "@/hooks/use-siem";
import { cn } from "@/lib/utils";

type SevFilter = "All" | Severity;

interface Props {
  api: SiemApi;
  onForensics: (e: NormalizedEvent) => void;
}

const fmtTs = (iso: string) => {
  const d = new Date(iso);
  return `${d.toISOString().slice(5, 10)} ${d.toTimeString().slice(0, 8)}`;
};

export function LogTable({ api, onForensics }: Props) {
  const [q, setQ] = useState("");
  const [sev, setSev] = useState<SevFilter>("All");
  const [alertsOnly, setAlertsOnly] = useState(false);

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return [...api.events]
      .reverse()
      .filter((e) => sev === "All" || e.severity === sev)
      .filter((e) => !alertsOnly || (e.rule !== undefined && e.severity !== "Info"))
      .filter((e) => {
        if (!needle) return true;
        return [e.sourceIp, e.user, e.asset, e.eventType, e.mitreId, e.rule?.title, e.rule?.id, e.id].some((v) => v?.toLowerCase().includes(needle));
      });
  }, [api.events, q, sev, alertsOnly]);

  const download = (content: string, mime: string, ext: string) => {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `nexussiem-audit-${new Date().toISOString().replace(/[:.]/g, "-")}.${ext}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const exportCsv = () => {
    const cols = ["id", "timestamp", "severity", "eventType", "sourceIp", "user", "asset", "logSource", "ruleId", "ruleTitle", "mitreId", "status"];
    const esc = (v: unknown) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    const lines = [
      cols.join(","),
      ...rows.map((e) =>
        [e.id, e.timestamp, e.severity, e.eventType, e.sourceIp, e.user, e.asset, e.logSource, e.rule?.id, e.rule?.title, e.mitreId, e.status].map(esc).join(","),
      ),
    ];
    download(lines.join("\n"), "text/csv", "csv");
  };

  const exportAudit = () => {
    const report = {
      generatedAt: new Date().toISOString(),
      platform: "NexusSIEM Pro Enterprise v4.0",
      filters: { query: q || null, severity: sev },
      summary: {
        totalIngested: api.metrics.total,
        activeAlerts: api.metrics.alerts,
        criticalHigh: api.metrics.criticalHigh,
        bySeverity: api.metrics.bySeverity,
        blockedIps: [...api.blockedIps],
        isolatedHosts: [...api.isolatedHosts],
        mitreTechniques: api.metrics.ttps,
      },
      events: rows.map((e) => ({ ...e, rule: e.rule ? { id: e.rule.id, title: e.rule.title, mitreId: e.rule.mitreId } : null })),
    };
    download(JSON.stringify(report, null, 2), "application/json", "json");
  };

  return (
    <section className="panel flex min-h-[480px] flex-col">
      <div className="flex flex-wrap items-center gap-2 border-b border-border p-3">
        <div className="panel-title mr-auto">
          <Terminal className="size-3.5 text-neon" /> Security Events &amp; Alerts
          <span className="telemetry rounded bg-neon/10 px-1.5 py-0.5 text-neon">{rows.length}</span>
        </div>
        <div className="relative">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter IP, user, MITRE ID, event type…" className="h-8 w-64 border-border bg-background/60 pl-8 font-mono text-xs" />
        </div>
        <Select value={sev} onValueChange={(v) => setSev(v as SevFilter)}>
          <SelectTrigger className="h-8 w-32 border-border bg-background/60 font-mono text-xs">
            <SelectValue />
          </SelectTrigger>
          <SelectContent className="font-mono text-xs">
            {(["All", "Critical", "High", "Medium", "Low"] as const).map((s) => (
              <SelectItem key={s} value={s}>{s}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button
          variant={alertsOnly ? "neon" : "panel"}
          size="sm"
          onClick={() => setAlertsOnly((v) => !v)}
          aria-pressed={alertsOnly}
        >
          Alerts only
        </Button>
        <Button variant="panel" size="sm" onClick={exportAudit} disabled={rows.length === 0}>
          <Download /> Export Audit Report
        </Button>
        <Button variant="panel" size="sm" onClick={exportCsv} disabled={rows.length === 0}>
          <FileSpreadsheet /> CSV
        </Button>
      </div>

      <div className="flex-1 overflow-auto">
        <table className="w-full text-left text-xs">
          <thead className="sticky top-0 z-10 bg-card/95 backdrop-blur">
            <tr className="border-b border-border font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
              <th className="px-3 py-2 font-medium">Severity</th>
              <th className="px-3 py-2 font-medium">Timestamp</th>
              <th className="px-3 py-2 font-medium">Event Type</th>
              <th className="px-3 py-2 font-medium">Source IP</th>
              <th className="px-3 py-2 font-medium">User / Asset</th>
              <th className="px-3 py-2 font-medium">Sigma Rule / MITRE</th>
              <th className="px-3 py-2 text-right font-medium">Action</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr>
                <td colSpan={7} className="px-3 py-16 text-center font-mono text-[11px] text-muted-foreground">
                  {api.events.length === 0 ? "Buffer empty — ingest logs, load the sample set, or start the live attack stream." : "No events match the current filter."}
                </td>
              </tr>
            )}
            {rows.map((e) => (
              <tr
                key={e.id}
                onClick={() => onForensics(e)}
                className={cn("animate-row-in cursor-pointer border-b border-border/50 transition-colors hover:bg-neon/5", e.status !== "open" && "opacity-60")}
              >
                <td className="px-3 py-2"><SeverityBadge severity={e.severity} /></td>
                <td className="telemetry whitespace-nowrap px-3 py-2 text-muted-foreground">{fmtTs(e.timestamp)}</td>
                <td className="whitespace-nowrap px-3 py-2 font-medium text-foreground">{e.eventType}</td>
                <td className="px-3 py-2">
                  <span className={cn("telemetry", api.blockedIps.has(e.sourceIp) ? "text-muted-foreground line-through" : "text-neon")}>{e.sourceIp}</span>
                  {api.blockedIps.has(e.sourceIp) && <ShieldBan className="ml-1 inline size-3 text-sev-critical" />}
                </td>
                <td className="px-3 py-2">
                  <div className="font-mono text-foreground">{e.user ?? "—"}</div>
                  <div className="flex items-center gap-1 font-mono text-[10px] text-muted-foreground">
                    {e.asset}
                    {api.isolatedHosts.has(e.asset) && <ShieldCheck className="size-3 text-success" />}
                  </div>
                </td>
                <td className="px-3 py-2">
                  {e.rule ? (
                    <>
                      <div className="text-foreground">{e.rule.title}</div>
                      <div className="font-mono text-[10px] text-neon">{e.rule.id} · {e.mitreId}</div>
                    </>
                  ) : (
                    <span className="font-mono text-[10px] text-muted-foreground">no match</span>
                  )}
                </td>
                <td className="px-3 py-2 text-right">
                  <Button variant="panel" size="sm" className="h-7 px-2" onClick={(ev) => { ev.stopPropagation(); onForensics(e); }}>
                    <Microscope /> Forensics
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
