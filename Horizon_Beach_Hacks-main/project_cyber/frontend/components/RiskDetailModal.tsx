"use client";

import { useState } from "react";
import { Bot, Play, Siren } from "lucide-react";
import { api, type Risk, type RiskStatus } from "@/lib/api";
import { useAction, useQuery } from "@/hooks/useQuery";
import { useAuth } from "@/contexts/AuthContext";
import { Async, Button, LevelBadge, Modal, fmtDate, inputClass, titleCase } from "@/components/ui";
import AgentDiscussionModal from "@/components/AgentDiscussionModal";
import PlaybookModal from "@/components/PlaybookModal";

const STATUSES: RiskStatus[] = ["active", "investigating", "mitigating", "resolved", "accepted"];

const COMPONENTS: [keyof NonNullable<Risk["components"]>, string][] = [
  ["cvss_score", "CVSS severity"],
  ["exploit_activity", "Exploit activity"],
  ["exposure_level", "Exposure"],
  ["asset_criticality", "Asset criticality"],
  ["business_impact", "Business impact"],
  ["ai_relevance", "AI relevance"],
];

export default function RiskDetailModal({ riskId, onClose, onChanged }: { riskId: string; onClose: () => void; onChanged?: () => void }) {
  const { can } = useAuth();
  const risk = useQuery(() => api.risks.get(riskId), [riskId]);
  const recs = useQuery(() => api.risks.playbooks(riskId), [riskId]);
  const [analysis, setAnalysis] = useState(false);
  const [executionId, setExecutionId] = useState<string | null>(null);
  const [notes, setNotes] = useState("");

  const setStatus = useAction((s: RiskStatus) => api.risks.setStatus(riskId, s, notes || undefined));
  const investigate = useAction(() => api.risks.investigate(riskId));
  const start = useAction((slug: string) => api.playbooks.start({ slug, risk_id: riskId }));
  const recalc = useAction(() => api.risks.recalculate(riskId));

  const refresh = async () => {
    await Promise.all([risk.refetch(), recs.refetch()]);
    onChanged?.();
  };
  const error = setStatus.error || investigate.error || start.error || recalc.error;

  return (
    <>
      <Modal title={<span className="line-clamp-2">{risk.data?.title ?? "Risk"}</span>} onClose={onClose} wide>
        <Async q={risk}>
          {(r) => (
            <div className="space-y-5">
              <div className="flex flex-wrap items-center gap-3">
                <LevelBadge level={r.level} />
                <span className="text-sm text-gray-700 dark:text-gray-200">BWVS <strong>{r.bwvs_score.toFixed(1)}</strong> · priority {r.priority_score.toFixed(1)}</span>
                <span className="text-xs text-gray-500 dark:text-gray-300">First seen {fmtDate(r.first_seen)} · last seen {fmtDate(r.last_seen)}</span>
              </div>
              {r.description && <p className="text-sm text-gray-700 dark:text-gray-200 whitespace-pre-wrap">{r.description}</p>}

              {r.components && (
                <div>
                  <h4 className="text-sm font-semibold mb-2 text-gray-900 dark:text-white">Business-Weighted Vulnerability Score</h4>
                  <div className="space-y-1.5">
                    {COMPONENTS.map(([key, label]) => (
                      <div key={key} className="flex items-center gap-2 text-xs">
                        <span className="w-32 text-gray-600 dark:text-gray-300">{label}</span>
                        <div className="flex-1 h-2 bg-gray-200 dark:bg-gray-700 rounded">
                          <div className="h-2 rounded bg-primary" style={{ width: `${Math.min(100, r.components![key])}%` }} />
                        </div>
                        <span className="w-10 text-right text-gray-700 dark:text-white">{r.components![key].toFixed(0)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div className="grid sm:grid-cols-2 gap-4 text-sm">
                {r.cve && (
                  <div className="p-3 rounded-md border border-gray-200 dark:border-gray-700">
                    <p className="font-semibold text-gray-900 dark:text-white">{r.cve.cve_id}</p>
                    <p className="text-xs text-gray-600 dark:text-gray-300">
                      CVSS {r.cve.cvss_score} {r.cve.severity && `(${r.cve.severity})`}
                      {r.cve.epss_score !== null && ` · EPSS ${(r.cve.epss_score * 100).toFixed(1)}%`}
                    </p>
                    <div className="flex gap-1.5 mt-1">
                      {r.cve.cisa_kev && <LevelBadge level="critical">CISA KEV</LevelBadge>}
                      {r.cve.has_exploit && <LevelBadge level="high">Exploit available</LevelBadge>}
                    </div>
                    <p className="text-xs mt-2 text-gray-700 dark:text-gray-200 line-clamp-5">{r.cve.description}</p>
                  </div>
                )}
                {r.asset && (
                  <div className="p-3 rounded-md border border-gray-200 dark:border-gray-700">
                    <p className="font-semibold text-gray-900 dark:text-white">{r.asset.name}</p>
                    <p className="text-xs text-gray-600 dark:text-gray-300">
                      {[r.asset.hostname, r.asset.ip_address].filter(Boolean).join(" · ")}
                    </p>
                    <p className="text-xs mt-1 text-gray-700 dark:text-gray-200">
                      {titleCase(r.asset.asset_type)} · {titleCase(r.asset.exposure_level)} · {titleCase(r.asset.criticality)}
                      {r.asset.business_unit && ` · ${r.asset.business_unit}`}
                    </p>
                    {r.asset.is_isolated && <p className="text-xs text-warning mt-1">Currently isolated</p>}
                  </div>
                )}
              </div>

              {r.match_reasons.length > 0 && (
                <div>
                  <h4 className="text-sm font-semibold mb-1 text-gray-900 dark:text-white">Why this risk exists</h4>
                  <ul className="list-disc list-inside text-xs text-gray-700 dark:text-gray-200 space-y-0.5">
                    {r.match_reasons.map((m, i) => <li key={i}>{m}</li>)}
                  </ul>
                </div>
              )}

              <div>
                <h4 className="text-sm font-semibold mb-2 text-gray-900 dark:text-white">Recommended playbooks</h4>
                <Async q={recs} empty={{ when: (d) => d.length === 0, title: "No playbook matches this risk" }}>
                  {(list) => (
                    <ul className="space-y-2">
                      {list.map((p) => (
                        <li key={p.playbook.id} className="flex items-center justify-between gap-3 p-2 rounded-md border border-gray-200 dark:border-gray-700">
                          <div className="min-w-0">
                            <p className="text-sm font-medium text-gray-900 dark:text-white">{p.playbook.name}</p>
                            <p className="text-xs text-gray-500 dark:text-gray-300 truncate">
                              {p.playbook.steps.length} steps · ~{p.playbook.estimated_duration} min · {p.reasons.join("; ")}
                            </p>
                          </div>
                          {can("analyst") && p.playbook.slug && (
                            <Button
                              disabled={start.pending}
                              onClick={async () => {
                                const ex = await start.run(p.playbook.slug!);
                                if (ex) {
                                  setExecutionId(ex.id);
                                  await refresh();
                                }
                              }}
                            >
                              <Play className="w-3 h-3" /> Run
                            </Button>
                          )}
                        </li>
                      ))}
                    </ul>
                  )}
                </Async>
              </div>

              {can("analyst") && (
                <div className="space-y-3 pt-3 border-t border-gray-200 dark:border-gray-700">
                  <div className="flex flex-wrap gap-2">
                    <Button onClick={() => setAnalysis(true)}><Bot className="w-4 h-4" /> Run AI agent analysis</Button>
                    <Button
                      variant="secondary"
                      disabled={investigate.pending}
                      onClick={async () => {
                        if (await investigate.run()) await refresh();
                      }}
                    >
                      <Siren className="w-4 h-4" /> Open incident
                    </Button>
                    <Button
                      variant="secondary"
                      disabled={recalc.pending}
                      onClick={async () => {
                        if (await recalc.run()) await refresh();
                      }}
                    >
                      Recalculate score
                    </Button>
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    <label className="text-sm text-gray-700 dark:text-gray-200" htmlFor="risk-status">Status</label>
                    <select
                      id="risk-status"
                      value={r.status}
                      disabled={setStatus.pending}
                      onChange={async (e) => {
                        if (await setStatus.run(e.target.value as RiskStatus)) {
                          setNotes("");
                          await refresh();
                        }
                      }}
                      className={`${inputClass} !w-auto`}
                    >
                      {STATUSES.map((s) => <option key={s} value={s}>{titleCase(s)}</option>)}
                    </select>
                    <input
                      value={notes}
                      onChange={(e) => setNotes(e.target.value)}
                      placeholder="Reason / notes for the status change"
                      className={`${inputClass} flex-1 min-w-48`}
                      maxLength={4000}
                    />
                  </div>
                  {r.remediation_notes && <p className="text-xs text-gray-600 dark:text-gray-300 whitespace-pre-wrap">{r.remediation_notes}</p>}
                  {error && <p className="text-sm text-critical" role="alert">{error}</p>}
                </div>
              )}
            </div>
          )}
        </Async>
      </Modal>
      {analysis && (
        <AgentDiscussionModal riskId={riskId} title={risk.data?.title ?? ""} onClose={() => setAnalysis(false)} onFinished={refresh} />
      )}
      {executionId && <PlaybookModal executionId={executionId} onClose={() => setExecutionId(null)} onChanged={refresh} />}
    </>
  );
}
