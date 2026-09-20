import { BookOpen, Globe2, Microscope, ShieldBan, ShieldCheck, Zap } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { SeverityBadge } from "./severity-badge";
import { SIGMA_RULES } from "@/lib/siem/sigma-rules";
import { lookupIp } from "@/lib/siem/threat-intel";
import type { NormalizedEvent } from "@/lib/siem/types";
import type { SiemApi } from "@/hooks/use-siem";
import { cn } from "@/lib/utils";

export function SigmaRulesModal({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[85vh] max-w-3xl overflow-y-auto border-border bg-card">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-foreground">
            <BookOpen className="size-4 text-neon" /> Sigma Rules Repository
          </DialogTitle>
          <DialogDescription className="font-mono text-xs">
            {SIGMA_RULES.length} detection rules loaded · {SIGMA_RULES.filter((r) => r.status === "active").length} active · evaluated on every ingested event
          </DialogDescription>
        </DialogHeader>
        <ul className="space-y-2">
          {SIGMA_RULES.map((r) => (
            <li key={r.id} className="rounded-md border border-border bg-background/50 p-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-xs text-neon">{r.id}</span>
                <span className="font-medium text-foreground">{r.title}</span>
                <SeverityBadge severity={r.severity} />
                <span className={cn("ml-auto rounded px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider", r.status === "active" ? "bg-success/15 text-success" : "bg-warning/15 text-warning")}>{r.status}</span>
              </div>
              <p className="mt-1.5 text-xs text-muted-foreground">{r.description}</p>
              <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 font-mono text-[10px] text-muted-foreground">
                <span>ATT&amp;CK: <span className="text-foreground">{r.mitreId}</span> {r.mitreName}</span>
                <span>Tactic: <span className="text-foreground">{r.tactic}</span></span>
                <span>Logsource: <span className="text-foreground">{r.logsource}</span></span>
              </div>
            </li>
          ))}
        </ul>
      </DialogContent>
    </Dialog>
  );
}

interface ForensicsProps {
  event: NormalizedEvent | null;
  api: SiemApi;
  onClose: () => void;
}

export function ForensicsModal({ event, api, onClose }: ForensicsProps) {
  const intel = event ? lookupIp(event.sourceIp) : null;
  const blocked = event ? api.blockedIps.has(event.sourceIp) : false;
  const isolated = event ? api.isolatedHosts.has(event.asset) : false;
  const schema = event
    ? {
        "@timestamp": event.timestamp,
        "event.id": event.id,
        "event.category": event.eventType,
        "event.severity": event.severity,
        "event.dataset": event.logSource,
        "source.ip": event.sourceIp,
        "destination.ip": event.destIp ?? null,
        "user.name": event.user ?? null,
        "host.name": event.asset,
        "rule.id": event.rule?.id ?? null,
        "rule.name": event.rule?.title ?? null,
        "threat.technique.id": event.mitreId ?? null,
        "threat.tactic.name": event.rule?.tactic ?? null,
        ...Object.fromEntries(Object.entries(event.meta).filter(([, v]) => v !== undefined).map(([k, v]) => [`meta.${k}`, v])),
      }
    : null;

  return (
    <Dialog open={!!event} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-h-[90vh] max-w-4xl overflow-y-auto border-border bg-card">
        {event && intel && schema && (
          <>
            <DialogHeader>
              <DialogTitle className="flex flex-wrap items-center gap-2 text-foreground">
                <Microscope className="size-4 text-neon" /> Forensic Inspector
                <span className="font-mono text-xs text-muted-foreground">{event.id}</span>
                <SeverityBadge severity={event.severity} />
              </DialogTitle>
              <DialogDescription className="font-mono text-xs">
                {event.eventType} · {event.rule ? `${event.rule.id} ${event.rule.title} · ${event.mitreId}` : "No Sigma rule matched"}
              </DialogDescription>
            </DialogHeader>

            <div className="grid gap-4 md:grid-cols-5">
              <div className="space-y-4 md:col-span-3">
                <div>
                  <div className="panel-title mb-1.5">Raw Payload</div>
                  <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded-md border border-border bg-background p-3 font-mono text-[11px] leading-relaxed text-neon/90">{event.raw}</pre>
                </div>
                <div>
                  <div className="panel-title mb-1.5">Normalized Schema (ECS)</div>
                  <div className="overflow-hidden rounded-md border border-border bg-background">
                    {Object.entries(schema).map(([k, v]) => (
                      <div key={k} className="grid grid-cols-[180px_1fr] gap-2 border-b border-border/50 px-3 py-1.5 font-mono text-[11px] last:border-0">
                        <span className="text-muted-foreground">{k}</span>
                        <span className="break-all text-foreground">{v === null ? <span className="text-muted-foreground/60">null</span> : String(v)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              <div className="space-y-4 md:col-span-2">
                <div>
                  <div className="panel-title mb-1.5"><Globe2 className="size-3" /> Source Reputation</div>
                  <div className={cn("rounded-md border p-3 font-mono text-[11px]", intel.malicious ? "border-sev-critical/40 bg-sev-critical/5" : "border-success/40 bg-success/5")}>
                    <div className="flex items-center justify-between">
                      <span className="text-foreground">{intel.ip}</span>
                      <span className={cn("font-bold uppercase", intel.malicious ? "text-sev-critical" : "text-success")}>{intel.malicious ? `Malicious ${intel.confidence}%` : "Clean"}</span>
                    </div>
                    <div className="mt-1 text-muted-foreground">{intel.city}, {intel.country} · {intel.asn}</div>
                    <div className="mt-2 flex flex-wrap gap-1">
                      {intel.tags.map((t) => <span key={t} className="rounded border border-border px-1.5 py-0.5 text-[10px] text-foreground">{t}</span>)}
                    </div>
                  </div>
                </div>

                <div>
                  <div className="panel-title mb-1.5"><Zap className="size-3" /> Autonomous SOAR Playbooks</div>
                  <div className="space-y-2">
                    <Button
                      variant={blocked ? "panel" : "danger"}
                      className="w-full justify-start"
                      onClick={() => (blocked ? api.unblockIp(event.sourceIp) : api.blockIp(event.sourceIp))}
                    >
                      <ShieldBan /> {blocked ? `Unblock ${event.sourceIp} (rollback)` : "Block Source IP at Firewall"}
                    </Button>
                    <Button
                      variant={isolated ? "panel" : "neon"}
                      className="w-full justify-start"
                      onClick={() => (isolated ? api.releaseHost(event.asset) : api.quarantine(event.asset))}
                    >
                      <ShieldCheck /> {isolated ? `Release ${event.asset} from isolation` : `Quarantine Endpoint (${event.asset})`}
                    </Button>
                  </div>
                  <ul className="mt-3 space-y-1 font-mono text-[10px] text-muted-foreground">
                    <li>› Block: pushes DENY rule to ufw + cloud security group, TTL 24h</li>
                    <li>› Quarantine: EDR network isolation, preserves memory image</li>
                    <li>› Every action is written to the immutable audit trail</li>
                  </ul>
                </div>

                <div className="rounded-md border border-border bg-background/50 p-3 font-mono text-[11px]">
                  <div className="text-muted-foreground">Containment status</div>
                  <div className={cn("mt-1 font-semibold uppercase tracking-wider", event.status === "open" ? "text-sev-medium" : "text-success")}>{event.status}</div>
                </div>
              </div>
            </div>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
