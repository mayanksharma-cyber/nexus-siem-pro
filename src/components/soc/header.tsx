import { BookOpen, Radio, ShieldHalf, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { cn } from "@/lib/utils";

interface Props {
  streaming: boolean;
  onToggleStream: () => void;
  onOpenRules: () => void;
  onPurge: () => void;
  streamRate: number;
  onStreamRateChange: (ms: number) => void;
}

const RATES = [
  { ms: 1000, label: "Fast · 1s" },
  { ms: 3500, label: "Normal · 3.5s" },
  { ms: 8000, label: "Slow · 8s" },
];

export function Header({ streaming, onToggleStream, onOpenRules, onPurge, streamRate, onStreamRateChange }: Props) {
  return (
    <header className="sticky top-0 z-30 border-b border-border/80 bg-background/80 backdrop-blur-md">
      <div className="mx-auto flex max-w-[1800px] flex-wrap items-center justify-between gap-4 px-4 py-3 lg:px-6">
        <div className="flex items-center gap-3">
          <div className="relative grid size-10 place-items-center rounded-lg border border-neon/40 bg-neon/10 shadow-glow">
            <ShieldHalf className="size-5 text-neon" />
            <span className="absolute -right-1 -top-1 size-2 rounded-full bg-neon animate-flicker" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-lg font-semibold tracking-tight text-foreground glow-text">NexusSIEM Pro</h1>
              <span className="rounded border border-neon/40 bg-neon/10 px-1.5 py-0.5 font-mono text-[10px] font-semibold tracking-widest text-neon">
                ENTERPRISE v4.0
              </span>
            </div>
            <p className="font-mono text-[11px] text-muted-foreground">
              Advanced Threat Hunting, Real-Time Sigma Engine &amp; Autonomous SOAR Playbooks
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Button variant={streaming ? "danger" : "neon"} size="sm" onClick={onToggleStream}>
            <span
              className={cn("status-dot", streaming ? "text-sev-critical" : "text-success")}
              style={{ ["--pulse-color" as string]: "currentColor" }}
            />
            <Radio />
            {streaming ? "Stop Live Attack Stream" : "Start Live Attack Stream"}
          </Button>
          <Select value={String(streamRate)} onValueChange={(v) => onStreamRateChange(Number(v))}>
            <SelectTrigger className="h-8 w-[150px] border-border bg-background/60 font-mono text-xs" aria-label="Stream rate">
              <SelectValue />
            </SelectTrigger>
            <SelectContent className="font-mono text-xs">
              {RATES.map((r) => (
                <SelectItem key={r.ms} value={String(r.ms)}>{r.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button variant="panel" size="sm" onClick={onOpenRules}>
            <BookOpen />
            Sigma Rules Repository
          </Button>
          <Button variant="panel" size="sm" onClick={onPurge} className="hover:border-destructive/50 hover:text-sev-critical">
            <Trash2 />
            Purge SIEM Buffer
          </Button>
        </div>
      </div>
    </header>
  );
}
