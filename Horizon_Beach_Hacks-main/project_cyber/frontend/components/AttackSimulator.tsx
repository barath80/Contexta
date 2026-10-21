"use client";

import { useState } from "react";
import { Play, Loader2 } from "lucide-react";
import { api, type SimulationResult, type TwinNode } from "@/lib/api";
import { useAction, useQuery } from "@/hooks/useQuery";
import { useAuth } from "@/contexts/AuthContext";
import { Async, Button, Card, EmptyState, LevelBadge, fmtLakhs, inputClass, titleCase } from "@/components/ui";

const ZONE_ORDER = ["external", "dmz", "internal", "restricted", "cloud"];
const RISK_DOT: Record<string, string> = {
  critical: "bg-red-500", high: "bg-orange-500", medium: "bg-yellow-400", low: "bg-blue-400", none: "bg-gray-300",
};

function Topology({ nodes, hit, entry }: { nodes: TwinNode[]; hit: Set<string>; entry?: string }) {
  const zones = ZONE_ORDER.map((z) => ({ zone: z, items: nodes.filter((n) => n.zone === z) })).filter((z) => z.items.length);
  return (
    <div className="space-y-3">
      {zones.map(({ zone, items }) => (
        <div key={zone}>
          <p className="text-xs uppercase font-semibold text-gray-500 dark:text-gray-300 mb-1">{zone}</p>
          <div className="flex flex-wrap gap-2">
            {items.map((n) => {
              const compromised = hit.has(n.id);
              return (
                <div
                  key={n.id}
                  title={`${titleCase(n.asset_type)} · ${titleCase(n.criticality)} · ${n.open_risks} open risk(s)`}
                  className={`px-2.5 py-1.5 rounded-md border text-xs flex items-center gap-1.5 ${
                    compromised
                      ? "border-critical bg-red-50 dark:bg-red-900/30 text-red-800 dark:text-red-200"
                      : "border-gray-200 dark:border-gray-600 text-gray-800 dark:text-gray-100"
                  } ${entry === n.id ? "ring-2 ring-critical" : ""}`}
                >
                  <span className={`w-2 h-2 rounded-full ${RISK_DOT[n.risk_level] ?? RISK_DOT.none}`} />
                  {n.name}
                  {n.is_isolated && <span className="text-warning">(isolated)</span>}
                </div>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}

export default function AttackSimulator() {
  const { can } = useAuth();
  const types = useQuery(() => api.twin.attackTypes(), []);
  const topo = useQuery(() => api.twin.topology(), []);
  const [attack, setAttack] = useState("ransomware");
  const [entry, setEntry] = useState("");
  const [target, setTarget] = useState("");
  const [result, setResult] = useState<SimulationResult | null>(null);
  const sim = useAction(() => api.twin.simulate({ attack_type: attack, entry_point: entry || undefined, target: target || undefined }));

  const run = async () => {
    const r = await sim.run();
    if (r) setResult(r);
  };
  const hit = new Set<string>([
    ...(result?.blast_radius.map((b) => b.id) ?? []),
    ...((result?.compromised_assets ?? []).map((a) => String(a.id))),
    ...(result ? [result.entry_point] : []),
  ]);
  const nodes = topo.data?.nodes ?? [];
  const chosen = types.data?.find((t) => t.id === attack);

  return (
    <div className="grid grid-cols-1 xl:grid-cols-3 gap-3">
      <div className="xl:col-span-2 space-y-3">
        <Card title="Attack path simulator (digital twin)">
          <div className="flex flex-wrap items-end gap-3 mb-4">
            <label className="text-sm">
              <span className="block mb-1 text-gray-700 dark:text-gray-200">Attack type</span>
              <select className={`${inputClass} !w-auto`} value={attack} onChange={(e) => setAttack(e.target.value)}>
                {(types.data ?? [{ id: "ransomware", label: "Ransomware" }]).map((t) => <option key={t.id} value={t.id}>{t.label}</option>)}
              </select>
            </label>
            <label className="text-sm">
              <span className="block mb-1 text-gray-700 dark:text-gray-200">Entry point</span>
              <select className={`${inputClass} !w-auto`} value={entry} onChange={(e) => setEntry(e.target.value)}>
                <option value="">Auto (most exposed)</option>
                {nodes.map((n) => <option key={n.id} value={n.id}>{n.name}</option>)}
              </select>
            </label>
            <label className="text-sm">
              <span className="block mb-1 text-gray-700 dark:text-gray-200">Target (optional)</span>
              <select className={`${inputClass} !w-auto`} value={target} onChange={(e) => setTarget(e.target.value)}>
                <option value="">Any critical asset</option>
                {nodes.map((n) => <option key={n.id} value={n.id}>{n.name}</option>)}
              </select>
            </label>
            {can("analyst") ? (
              <Button onClick={run} disabled={sim.pending || nodes.length === 0}>
                {sim.pending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />} {sim.pending ? "Running…" : "Run simulation"}
              </Button>
            ) : (
              <span className="text-xs text-gray-500 dark:text-gray-300">Analyst role required to run simulations.</span>
            )}
          </div>
          {chosen && <p className="text-xs text-gray-600 dark:text-gray-300 mb-3">{chosen.method} · time to impact: {chosen.time_to_impact}</p>}
          {sim.error && <p className="text-sm text-critical mb-2" role="alert">{sim.error}</p>}
          <Async q={topo} empty={{ when: (d) => d.nodes.length === 0, title: "No assets in the network graph", hint: "Add assets and connections in the Assets view to model your network." }}>
            {(t) => <Topology nodes={t.nodes} hit={hit} entry={result?.entry_point} />}
          </Async>
        </Card>

        {result && (
          <Card title={`Attack paths — ${result.attack_label} from ${result.entry_point_name}`}>
            {result.paths_found.length === 0 ? (
              <EmptyState title="No path to a critical asset" hint="Segmentation is containing this scenario from the chosen entry point." />
            ) : (
              <ol className="space-y-2">
                {result.paths_found.map((p, i) => (
                  <li key={i} className="p-2 rounded border border-gray-200 dark:border-gray-700 text-sm text-gray-900 dark:text-white">
                    {(p.path_names ?? []).join("  →  ")}
                    <span className="ml-2 text-xs text-gray-500 dark:text-gray-300">{String(p.hops ?? "")} hops · path risk {String(p.risk_score ?? "")}</span>
                  </li>
                ))}
              </ol>
            )}
            {result.timeline.length > 0 && (
              <div className="mt-4">
                <h4 className="text-sm font-semibold mb-2 text-gray-900 dark:text-white">Propagation timeline</h4>
                <ol className="space-y-1 text-xs text-gray-700 dark:text-gray-200">
                  {result.timeline.map((t, i) => (
                    <li key={i}>
                      <strong>Step {String(t.step)}:</strong> {(t.newly_compromised as string[]).join(", ")} <span className="text-gray-500">({String(t.total)} total)</span>
                    </li>
                  ))}
                </ol>
              </div>
            )}
          </Card>
        )}
      </div>

      <div className="space-y-3">
        <Card title="Impact assessment">
          {!result ? (
            <EmptyState title="No simulation yet" hint="Choose an attack and run it to see compromised assets and estimated loss, computed from your inventory." />
          ) : (
            <div className="space-y-3 text-sm text-gray-800 dark:text-gray-100">
              <div className="flex items-center justify-between"><span>Risk assessment</span><LevelBadge level={result.risk_assessment.toLowerCase()} /></div>
              <div className="flex justify-between"><span>Assets compromised</span><strong>{result.impact.assets_compromised} / {result.impact.assets_total}</strong></div>
              <div className="flex justify-between"><span>Revenue at risk / day</span><strong>{fmtLakhs(result.impact.daily_revenue_at_risk_lakhs)}</strong></div>
              <div className="flex justify-between"><span>Estimated downtime</span><strong>{result.impact.estimated_downtime_days} days</strong></div>
              <div className="flex justify-between"><span>Estimated loss</span><strong className="text-critical">{fmtLakhs(result.impact.estimated_loss_lakhs)}</strong></div>
              <div className="flex justify-between"><span>Time to impact</span><strong>{result.impact.time_to_impact}</strong></div>
              {result.critical_assets_compromised.length > 0 && (
                <div>
                  <p className="font-semibold mb-1">Critical assets reached</p>
                  <ul className="list-disc list-inside text-xs">{result.critical_assets_compromised.map((a) => <li key={String(a.id)}>{String(a.name)}</li>)}</ul>
                </div>
              )}
              {result.recommendations && result.recommendations.length > 0 && (
                <div>
                  <p className="font-semibold mb-1">Recommendations</p>
                  <ul className="list-disc list-inside text-xs space-y-0.5">{result.recommendations.map((r, i) => <li key={i}>{r}</li>)}</ul>
                </div>
              )}
              {Array.isArray(result.assumptions) && (
                <details className="text-xs text-gray-500 dark:text-gray-300">
                  <summary className="cursor-pointer">Assumptions</summary>
                  <ul className="list-disc list-inside mt-1">{(result.assumptions as string[]).map((a, i) => <li key={i}>{a}</li>)}</ul>
                </details>
              )}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
