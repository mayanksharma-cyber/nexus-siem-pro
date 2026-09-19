import { Activity, Bell, Flame, ShieldBan } from "lucide-react";
import type { SiemApi } from "@/hooks/use-siem";
import { cn } from "@/lib/utils";

export function KpiCards({ metrics }: { metrics: SiemApi["metrics"] }) {
  const cards = [
    { label: "Total Ingested Events", value: metrics.total, sub: `${metrics.buffered} in hot buffer`, icon: Activity, tone: "text-neon" },
    { label: "Active Security Alerts", value: metrics.alerts, sub: "Sigma rule matches", icon: Bell, tone: "text-sev-medium" },
    { label: "Critical / High Severity", value: metrics.criticalHigh, sub: `${metrics.bySeverity.Critical} critical · ${metrics.bySeverity.High} high`, icon: Flame, tone: "text-sev-critical" },
    { label: "Isolated Hosts / Blocked IPs", value: metrics.contained, sub: "SOAR containment actions", icon: ShieldBan, tone: "text-success" },
  ];
  return (
    <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">
      {cards.map((c) => (
        <div key={c.label} className="panel p-4">
          <div className="flex items-start justify-between">
            <span className="panel-title">{c.label}</span>
            <c.icon className={cn("size-4", c.tone)} />
          </div>
          <div className={cn("telemetry mt-3 text-3xl font-semibold leading-none", c.tone)}>{c.value.toLocaleString()}</div>
          <div className="mt-2 font-mono text-[11px] text-muted-foreground">{c.sub}</div>
        </div>
      ))}
    </div>
  );
}
