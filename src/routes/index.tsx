import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { Header } from "@/components/soc/header";
import { KpiCards } from "@/components/soc/kpi-cards";
import { Charts } from "@/components/soc/charts";
import { Sidebar } from "@/components/soc/sidebar";
import { LogTable } from "@/components/soc/log-table";
import { ForensicsModal, SigmaRulesModal } from "@/components/soc/modals";
import { useSiem } from "@/hooks/use-siem";
import type { NormalizedEvent } from "@/lib/siem/types";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "NexusSIEM Pro — Enterprise Security Operations Center" },
      { name: "description", content: "Real-time SIEM & SOAR dashboard: Sigma detection engine, MITRE ATT&CK mapping, threat intel enrichment and autonomous response playbooks." },
      { property: "og:title", content: "NexusSIEM Pro — Enterprise SOC" },
      { property: "og:description", content: "Advanced threat hunting, real-time Sigma engine and autonomous SOAR playbooks." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Dashboard,
});

function Dashboard() {
  const api = useSiem();
  const [rulesOpen, setRulesOpen] = useState(false);
  const [inspecting, setInspecting] = useState<NormalizedEvent | null>(null);

  return (
    <div className="min-h-screen">
      <Header streaming={api.streaming} onToggleStream={api.toggleStream} onOpenRules={() => setRulesOpen(true)} onPurge={api.purge} />

      <main className="mx-auto flex max-w-[1800px] flex-col gap-3 p-4 lg:p-6">
        <KpiCards metrics={api.metrics} />
        <Charts metrics={api.metrics} />
        <div className="grid gap-3 xl:grid-cols-[340px_1fr]">
          <Sidebar api={api} lookupTarget={inspecting?.sourceIp ?? null} />
          <LogTable api={api} onForensics={setInspecting} />
        </div>
      </main>

      <footer className="mx-auto max-w-[1800px] px-4 pb-6 font-mono text-[10px] uppercase tracking-widest text-muted-foreground lg:px-6">
        NexusSIEM Pro · Sigma engine {api.streaming ? "streaming" : "idle"} · buffer {api.metrics.buffered}/600 · all processing client-side
      </footer>

      <SigmaRulesModal open={rulesOpen} onOpenChange={setRulesOpen} />
      <ForensicsModal event={inspecting} api={api} onClose={() => setInspecting(null)} />
    </div>
  );
}
