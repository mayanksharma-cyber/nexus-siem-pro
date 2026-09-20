import { useRef, useState } from "react";
import { Crosshair, FileUp, Globe2, RotateCcw, ScanSearch, Search, ShieldBan, ShieldCheck, Sparkles } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import type { SiemApi } from "@/hooks/use-siem";
import { isValidIp, lookupIp } from "@/lib/siem/threat-intel";
import type { ThreatIntel } from "@/lib/siem/types";
import { cn } from "@/lib/utils";

interface Props {
  api: SiemApi;
  lookupTarget: string | null;
}

export function Sidebar({ api, lookupTarget }: Props) {
  const [raw, setRaw] = useState("");
  const [ipQuery, setIpQuery] = useState("");
  const [intel, setIntel] = useState<ThreatIntel | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const lastTarget = useRef<string | null>(null);

  if (lookupTarget && lookupTarget !== lastTarget.current) {
    lastTarget.current = lookupTarget;
    setIpQuery(lookupTarget);
    setIntel(lookupIp(lookupTarget));
    setError(null);
  }

  const runLookup = (ip = ipQuery.trim()) => {
    if (!isValidIp(ip)) {
      setError("Enter a valid IPv4 address");
      setIntel(null);
      return;
    }
    setError(null);
    setIntel(lookupIp(ip));
  };

  const onFile = async (f: File | undefined) => {
    if (!f) return;
    const text = await f.text();
    setRaw(text);
    api.ingestRaw(text);
  };

  return (
    <aside className="flex flex-col gap-3">
      {/* Ingestion */}
      <section className="panel p-4">
        <div className="panel-title">
          <ScanSearch className="size-3.5 text-neon" /> Raw Log Ingestion Pipeline
        </div>
        <Textarea
          value={raw}
          onChange={(e) => setRaw(e.target.value)}
          placeholder={"Paste syslog / sshd / nginx / apache / UFW lines…\n\nSep 19 14:02:11 bastion-01 sshd[2211]: Failed password for root from 218.92.0.107 port 51122 ssh2"}
          className="mt-3 h-36 resize-none border-border bg-background/60 font-mono text-[11px] leading-relaxed placeholder:text-muted-foreground/60"
        />
        <div className="mt-3 flex flex-wrap gap-2">
          <Button variant="neon" size="sm" onClick={() => api.ingestRaw(raw)} disabled={!raw.trim()}>
            <Sparkles /> Normalize &amp; Scan
          </Button>
          <Button variant="panel" size="sm" onClick={() => fileRef.current?.click()}>
            <FileUp /> Upload
          </Button>
          <Button variant="ghost" size="sm" className="font-mono text-xs text-muted-foreground" onClick={() => api.loadSample()}>
            Load sample set
          </Button>
          <input ref={fileRef} type="file" accept=".log,.txt,text/plain" className="hidden" onChange={(e) => void onFile(e.target.files?.[0])} />
        </div>
      </section>

      {/* Threat intel */}
      <section className="panel p-4">
        <div className="panel-title">
          <Globe2 className="size-3.5 text-neon" /> Threat Intelligence Enrichment
        </div>
        <form
          className="mt-3 flex gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            runLookup();
          }}
        >
          <Input value={ipQuery} onChange={(e) => setIpQuery(e.target.value)} placeholder="185.220.101.47" className="border-border bg-background/60 font-mono text-xs" />
          <Button type="submit" variant="neon" size="sm" className="shrink-0">
            <Search /> Lookup
          </Button>
        </form>
        {error && <p className="mt-2 font-mono text-[11px] text-sev-critical">{error}</p>}
        {intel && (
          <div className={cn("mt-3 rounded-md border p-3 font-mono text-[11px]", intel.malicious ? "border-sev-critical/40 bg-sev-critical/5" : "border-success/40 bg-success/5")}>
            <div className="flex items-center justify-between">
              <span className="text-sm font-semibold text-foreground">{intel.ip}</span>
              <span className={cn("rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider", intel.malicious ? "bg-sev-critical/20 text-sev-critical" : "bg-success/20 text-success")}>
                {intel.malicious ? "Malicious" : "Clean"}
              </span>
            </div>
            <div className="mt-2 grid grid-cols-2 gap-x-3 gap-y-1 text-muted-foreground">
              <span>Geo</span>
              <span className="text-foreground">{intel.city}, {intel.country}</span>
              <span>ASN</span>
              <span className="truncate text-foreground" title={intel.asn}>{intel.asn}</span>
              <span>Reports</span>
              <span className="text-foreground">{intel.reports.toLocaleString()}</span>
              <span>Last seen</span>
              <span className="text-foreground">{intel.lastSeen}</span>
            </div>
            <div className="mt-2">
              <div className="flex justify-between text-muted-foreground">
                <span>Confidence</span>
                <span className="telemetry text-foreground">{intel.confidence}%</span>
              </div>
              <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-muted">
                <div className={cn("h-full rounded-full transition-all", intel.malicious ? "bg-sev-critical" : "bg-success")} style={{ width: `${intel.confidence}%` }} />
              </div>
            </div>
            <div className="mt-2 flex flex-wrap gap-1">
              {intel.tags.map((t) => (
                <span key={t} className="rounded border border-border bg-surface-raised px-1.5 py-0.5 text-[10px] text-foreground">{t}</span>
              ))}
            </div>
          </div>
        )}
      </section>

      {/* Containment */}
      {(api.blockedIps.size > 0 || api.isolatedHosts.size > 0) && (
        <section className="panel p-4">
          <div className="panel-title">
            <ShieldBan className="size-3.5 text-neon" /> Active Containment
          </div>
          <ul className="mt-3 space-y-1.5">
            {[...api.blockedIps].map((ip) => (
              <li key={`ip-${ip}`} className="flex items-center gap-2 rounded border border-sev-critical/30 bg-sev-critical/5 px-2.5 py-1.5">
                <ShieldBan className="size-3.5 shrink-0 text-sev-critical" />
                <div className="min-w-0 flex-1">
                  <div className="telemetry truncate text-foreground">{ip}</div>
                  <div className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">firewall deny</div>
                </div>
                <Button variant="ghost" size="sm" className="h-7 px-2 font-mono text-[10px]" onClick={() => api.unblockIp(ip)}>
                  <RotateCcw /> Undo
                </Button>
              </li>
            ))}
            {[...api.isolatedHosts].map((h) => (
              <li key={`host-${h}`} className="flex items-center gap-2 rounded border border-success/30 bg-success/5 px-2.5 py-1.5">
                <ShieldCheck className="size-3.5 shrink-0 text-success" />
                <div className="min-w-0 flex-1">
                  <div className="truncate font-mono text-xs text-foreground">{h}</div>
                  <div className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">edr isolation</div>
                </div>
                <Button variant="ghost" size="sm" className="h-7 px-2 font-mono text-[10px]" onClick={() => api.releaseHost(h)}>
                  <RotateCcw /> Release
                </Button>
              </li>
            ))}
          </ul>
        </section>
      )}

      {/* TTPs */}
      <section className="panel p-4">
        <div className="panel-title">
          <Crosshair className="size-3.5 text-neon" /> Active ATT&amp;CK TTPs
        </div>
        {api.metrics.ttps.length === 0 ? (
          <p className="mt-3 font-mono text-[11px] text-muted-foreground">No techniques triggered yet.</p>
        ) : (
          <ul className="mt-3 space-y-1.5">
            {api.metrics.ttps.map((t) => (
              <li key={t.id} className="flex items-center justify-between gap-2 rounded border border-border/60 bg-background/40 px-2.5 py-1.5">
                <div className="min-w-0">
                  <div className="font-mono text-xs text-neon">{t.id}</div>
                  <div className="truncate text-[11px] text-foreground">{t.name}</div>
                  <div className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">{t.tactic}</div>
                </div>
                <span className="telemetry shrink-0 rounded bg-neon/10 px-1.5 py-0.5 text-xs text-neon">{t.count}</span>
              </li>
            ))}
          </ul>
        )}
      </section>
    </aside>
  );
}
