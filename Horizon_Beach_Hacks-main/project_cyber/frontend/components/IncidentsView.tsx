"use client";

import { useState } from "react";
import { Bot } from "lucide-react";
import { api, type Incident, type IncidentStatus } from "@/lib/api";
import { useAction, useQuery } from "@/hooks/useQuery";
import { useAuth } from "@/contexts/AuthContext";
import { Async, Button, Card, LevelBadge, Modal, fmtDate, inputClass, timeAgo, titleCase } from "@/components/ui";
import Pager from "@/components/Pager";
import AgentDiscussionModal from "@/components/AgentDiscussionModal";

const PAGE_SIZE = 25;
const STATUSES: IncidentStatus[] = ["open", "analyzing", "responding", "contained", "resolved", "closed"];

function IncidentDetail({ id, onClose, onChanged }: { id: string; onClose: () => void; onChanged: () => void }) {
  const { can } = useAuth();
  const q = useQuery(() => api.incidents.get(id), [id]);
  const [note, setNote] = useState("");
  const [resolution, setResolution] = useState("");
  const [analysis, setAnalysis] = useState(false);

  const done = async (r: unknown) => {
    if (r) {
      await q.refetch();
      onChanged();
    }
  };
  const addNote = useAction(async () => { const r = await api.incidents.addNote(id, note); setNote(""); return r; });
  const setStatus = useAction((s: IncidentStatus) => api.incidents.update(id, { status: s }));
  const close = useAction(() => api.incidents.close(id, resolution));
  const error = addNote.error || setStatus.error || close.error;
  const inc: Incident | null = q.data;
  const closed = inc?.status === "closed" || inc?.status === "resolved";

  return (
    <>
      <Modal wide onClose={onClose} title={inc ? `${inc.ref ?? ""} ${inc.title}` : "Incident"}>
        <Async q={q}>
          {(i) => (
            <div className="space-y-4 text-sm text-gray-800 dark:text-gray-100">
              <div className="flex flex-wrap items-center gap-3">
                <LevelBadge level={i.severity} />
                <span className="font-medium">{titleCase(i.status)}</span>
                <span className="text-xs text-gray-500 dark:text-gray-300">Opened {fmtDate(i.created_at)}</span>
                {i.assigned_to && <span className="text-xs">Assigned to {i.assigned_to}</span>}
              </div>
              {i.description && <p className="whitespace-pre-wrap">{i.description}</p>}
              {i.affected_asset_names.length > 0 && (
                <p><span className="font-semibold">Affected assets:</span> {i.affected_asset_names.join(", ")}</p>
              )}
              {i.risk_title && <p><span className="font-semibold">Linked risk:</span> {i.risk_title} (BWVS {i.risk_bwvs?.toFixed(0)})</p>}
              {i.resolution && <p className="p-2 rounded bg-green-50 dark:bg-gray-900"><span className="font-semibold">Resolution:</span> {i.resolution}</p>}

              <div>
                <h4 className="font-semibold mb-2">Timeline</h4>
                <ol className="border-l-2 border-gray-200 dark:border-gray-700 ml-2 space-y-2">
                  {[...i.timeline].reverse().map((t, idx) => (
                    <li key={idx} className="pl-4 relative">
                      <span className="absolute -left-[5px] top-1.5 w-2 h-2 rounded-full bg-primary" />
                      <p className="text-sm">{t.event}</p>
                      {t.details && <p className="text-xs text-gray-600 dark:text-gray-300">{t.details}</p>}
                      <p className="text-xs text-gray-500 dark:text-gray-400">{fmtDate(t.timestamp)}{t.actor && ` · ${t.actor}`}</p>
                    </li>
                  ))}
                </ol>
              </div>

              {can("analyst") && !closed && (
                <div className="space-y-3 pt-3 border-t border-gray-200 dark:border-gray-700">
                  <div className="flex flex-wrap items-center gap-2">
                    <Button onClick={() => setAnalysis(true)}><Bot className="w-4 h-4" /> AI agent analysis</Button>
                    <select
                      aria-label="Change status"
                      value={i.status}
                      disabled={setStatus.pending}
                      onChange={async (e) => done(await setStatus.run(e.target.value as IncidentStatus))}
                      className={`${inputClass} !w-auto`}
                    >
                      {STATUSES.filter((s) => s !== "closed").map((s) => <option key={s} value={s}>{titleCase(s)}</option>)}
                    </select>
                  </div>
                  <div className="flex gap-2">
                    <input value={note} onChange={(e) => setNote(e.target.value)} placeholder="Add an investigation note…" className={inputClass} maxLength={4000} />
                    <Button disabled={!note.trim() || addNote.pending} onClick={async () => done(await addNote.run())}>Add</Button>
                  </div>
                  <div className="flex gap-2">
                    <input value={resolution} onChange={(e) => setResolution(e.target.value)} placeholder="Resolution summary (required to close)" className={inputClass} maxLength={4000} />
                    <Button variant="danger" disabled={resolution.trim().length < 3 || close.pending} onClick={async () => done(await close.run())}>Close incident</Button>
                  </div>
                  {error && <p className="text-critical" role="alert">{error}</p>}
                </div>
              )}
            </div>
          )}
        </Async>
      </Modal>
      {analysis && inc && <AgentDiscussionModal incidentId={id} title={inc.title} onClose={() => setAnalysis(false)} onFinished={q.refetch} />}
    </>
  );
}

export default function IncidentsView({ initialQuery = "" }: { initialQuery?: string }) {
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<string | null>(null);
  const list = useQuery(() => api.incidents.list({ page, page_size: PAGE_SIZE, status, severity, q: initialQuery }), [page, status, severity, initialQuery], 30000);

  return (
    <Card title="Incidents">
      <div className="flex flex-wrap gap-2 mb-3">
        <select value={status} onChange={(e) => { setStatus(e.target.value); setPage(1); }} aria-label="Status" className={`${inputClass} !w-auto`}>
          <option value="">Any status</option>
          {STATUSES.map((s) => <option key={s} value={s}>{titleCase(s)}</option>)}
        </select>
        <select value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1); }} aria-label="Severity" className={`${inputClass} !w-auto`}>
          <option value="">Any severity</option>
          {["critical", "high", "medium", "low"].map((s) => <option key={s} value={s}>{titleCase(s)}</option>)}
        </select>
      </div>
      <Async q={list} empty={{ when: (d) => d.total === 0, title: "No incidents", hint: "Open an incident from a risk's detail panel to start tracking an investigation." }}>
        {(d) => (
          <>
            <ul className="divide-y divide-gray-100 dark:divide-gray-700">
              {d.items.map((i) => (
                  <li key={i.id}>
                    <button onClick={() => setSelected(i.id)} className="w-full text-left py-2 flex items-center gap-3 hover:bg-gray-50 dark:hover:bg-gray-700/50 px-1 rounded">
                      <LevelBadge level={i.severity} />
                      <span className="flex-1 min-w-0">
                        <span className="block text-sm font-medium text-gray-900 dark:text-white truncate">{i.ref} · {i.title}</span>
                        <span className="block text-xs text-gray-500 dark:text-gray-300 truncate">{i.affected_asset_names.join(", ") || "No assets linked"} · {timeAgo(i.created_at)}</span>
                      </span>
                      <span className="text-xs font-medium text-gray-700 dark:text-gray-200">{titleCase(i.status)}</span>
                    </button>
                  </li>
              ))}
            </ul>
            <Pager page={page} pageSize={PAGE_SIZE} total={d.total} onPage={setPage} />
          </>
        )}
      </Async>
      {selected && <IncidentDetail id={selected} onClose={() => setSelected(null)} onChanged={list.refetch} />}
    </Card>
  );
}
