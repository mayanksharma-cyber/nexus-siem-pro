import { cn } from "@/lib/utils";
import type { Severity } from "@/lib/siem/types";

const STYLES: Record<Severity, string> = {
  Critical: "bg-sev-critical/15 text-sev-critical border-sev-critical/40",
  High: "bg-sev-high/15 text-sev-high border-sev-high/40",
  Medium: "bg-sev-medium/15 text-sev-medium border-sev-medium/40",
  Low: "bg-sev-low/15 text-sev-low border-sev-low/40",
  Info: "bg-muted text-muted-foreground border-border",
};

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded border px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider",
        STYLES[severity],
        className,
      )}
    >
      <span className={cn("size-1.5 rounded-full bg-current", severity === "Critical" && "animate-pulse")} />
      {severity}
    </span>
  );
}
