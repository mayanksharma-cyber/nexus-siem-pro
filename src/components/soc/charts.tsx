import { Bar, BarChart, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { PieChart as PieIcon, BarChart3 } from "lucide-react";
import type { SiemApi } from "@/hooks/use-siem";

const SEV_COLORS: Record<string, string> = {
  Critical: "var(--sev-critical)",
  High: "var(--sev-high)",
  Medium: "var(--sev-medium)",
  Low: "var(--sev-low)",
};

const tooltipStyle = {
  contentStyle: { background: "var(--popover)", border: "1px solid var(--border)", borderRadius: 6, fontFamily: "var(--font-mono)", fontSize: 11 },
  itemStyle: { color: "var(--foreground)" },
  labelStyle: { color: "var(--muted-foreground)" },
  cursor: { fill: "var(--neon-dim)" },
};

export function Charts({ metrics }: { metrics: SiemApi["metrics"] }) {
  const sevData = (["Critical", "High", "Medium", "Low"] as const).map((k) => ({ name: k, value: metrics.bySeverity[k] }));
  const hasSev = sevData.some((d) => d.value > 0);
  const typeData = metrics.byType.slice(0, 6);

  return (
    <div className="grid gap-3 lg:grid-cols-5">
      <div className="panel p-4 lg:col-span-2">
        <div className="panel-title">
          <PieIcon className="size-3.5 text-neon" /> Severity Distribution
        </div>
        <div className="mt-2 flex items-center gap-4">
          <div className="h-44 w-44 shrink-0">
            {hasSev ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={sevData} dataKey="value" nameKey="name" innerRadius={52} outerRadius={78} paddingAngle={3} stroke="var(--card)" strokeWidth={2} isAnimationActive={false}>
                    {sevData.map((d) => (
                      <Cell key={d.name} fill={SEV_COLORS[d.name]} />
                    ))}
                  </Pie>
                  <Tooltip {...tooltipStyle} />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="grid h-full place-items-center rounded-full border border-dashed border-border font-mono text-[11px] text-muted-foreground">NO DATA</div>
            )}
          </div>
          <ul className="flex-1 space-y-2">
            {sevData.map((d) => (
              <li key={d.name} className="flex items-center justify-between font-mono text-xs">
                <span className="flex items-center gap-2 text-muted-foreground">
                  <span className="size-2 rounded-sm" style={{ background: SEV_COLORS[d.name] }} />
                  {d.name}
                </span>
                <span className="telemetry text-foreground">{d.value}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>

      <div className="panel p-4 lg:col-span-3">
        <div className="panel-title">
          <BarChart3 className="size-3.5 text-neon" /> Top Attack Categories
        </div>
        <div className="mt-2 h-44">
          {typeData.length ? (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={typeData} layout="vertical" margin={{ left: 8, right: 24, top: 4, bottom: 4 }}>
                <XAxis type="number" hide />
                <YAxis type="category" dataKey="name" width={130} tick={{ fill: "var(--muted-foreground)", fontSize: 11, fontFamily: "var(--font-mono)" }} axisLine={false} tickLine={false} />
                <Tooltip {...tooltipStyle} />
                <Bar dataKey="value" radius={[0, 4, 4, 0]} isAnimationActive={false} label={{ position: "right", fill: "var(--neon)", fontSize: 11, fontFamily: "var(--font-mono)" }}>
                  {typeData.map((_, i) => (
                    <Cell key={i} fill={i === 0 ? "var(--neon)" : "var(--chart-5)"} fillOpacity={1 - i * 0.12} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="grid h-full place-items-center font-mono text-[11px] text-muted-foreground">AWAITING TELEMETRY — ingest logs or start the live stream</div>
          )}
        </div>
      </div>
    </div>
  );
}
