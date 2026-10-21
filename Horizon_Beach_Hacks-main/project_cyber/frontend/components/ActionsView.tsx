"use client";

import { useState } from "react";
import { Clock, Cog, Hand } from "lucide-react";
import { api, type Playbook } from "@/lib/api";
import { useQuery } from "@/hooks/useQuery";
import { Async, Card, LevelBadge, Modal, timeAgo, titleCase } from "@/components/ui";
import PlaybookModal from "@/components/PlaybookModal";

const STATUS_STYLE: Record<string, string> = {
  running: "text-primary",
  completed: "text-success",
  failed: "text-critical",
  cancelled: "text-gray-500",
  pending: "text-gray-500",
};

function PlaybookPreview({ pb, onClose }: { pb: Playbook; onClose: () => void }) {
  return (
    <Modal title={pb.name} onClose={onClose} wide>
      <p className="text-sm text-gray-700 dark:text-gray-200 mb-4">{pb.description}</p>
      <ol className="space-y-2">
        {pb.steps.map((s) => (
          <li key={s.order} className="p-3 rounded-md border border-gray-200 dark:border-gray-700">
            <p className="text-sm font-medium text-gray-900 dark:text-white flex items-center gap-2">
              {s.order}. {s.name}
              <span className="inline-flex items-center gap-1 text-xs text-gray-500 dark:text-gray-300">
                {s.action_type === "automated" ? <Cog className="w-3 h-3" /> : <Hand className="w-3 h-3" />} {s.action_type}
              </span>
            </p>
            <p className="text-xs text-gray-600 dark:text-gray-300 mt-0.5">{s.description}</p>
          </li>
        ))}
      </ol>
      <p className="text-xs text-gray-500 dark:text-gray-300 mt-4">
        Playbooks are started from a risk's detail panel so every execution is tied to the risk it remediates.
      </p>
    </Modal>
  );
}

export default function ActionsView() {
  const playbooks = useQuery(() => api.playbooks.list(), []);
  const executions = useQuery(() => api.playbooks.executions({ page_size: 20 }), [], 15000);
  const [preview, setPreview] = useState<Playbook | null>(null);
  const [execId, setExecId] = useState<string | null>(null);

  return (
    <div className="grid grid-cols-1 xl:grid-cols-2 gap-3">
      <Card title="Response playbooks">
        <Async q={playbooks} empty={{ when: (d) => d.length === 0, title: "No playbooks loaded" }}>
          {(list) => (
            <ul className="space-y-2">
              {list.map((p) => (
                <li key={p.id}>
                  <button onClick={() => setPreview(p)} className="w-full text-left p-3 rounded-md border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700/50">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-medium text-sm text-gray-900 dark:text-white">{p.name}</span>
                      <LevelBadge level={p.severity_threshold}>≥ {p.severity_threshold}</LevelBadge>
                    </div>
                    <p className="text-xs text-gray-600 dark:text-gray-300 mt-1 line-clamp-2">{p.description}</p>
                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-1 flex items-center gap-3">
                      <span>{titleCase(p.category)}</span>
                      <span className="inline-flex items-center gap-1"><Clock className="w-3 h-3" /> ~{p.estimated_duration} min</span>
                      <span>{p.manual_steps} manual · {p.automated_steps} automated</span>
                      {!p.is_active && <span className="text-warning">disabled</span>}
                    </p>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Async>
      </Card>

      <Card title="Recent executions">
        <Async q={executions} empty={{ when: (d) => d.total === 0, title: "No executions yet", hint: "Run a recommended playbook from a risk's detail panel." }}>
          {(d) => (
            <ul className="space-y-2">
              {d.items.map((e) => (
                <li key={e.id}>
                  <button onClick={() => setExecId(e.id)} className="w-full text-left p-3 rounded-md border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700/50">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-medium text-sm text-gray-900 dark:text-white truncate">{e.playbook_name}</span>
                      <span className={`text-xs font-semibold uppercase ${STATUS_STYLE[e.status] ?? ""}`}>{e.status}</span>
                    </div>
                    <p className="text-xs text-gray-500 dark:text-gray-300 truncate">{e.risk_title ?? "No linked risk"} · {timeAgo(e.started_at ?? e.created_at)}</p>
                    <div className="h-1.5 mt-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                      <div className="h-full bg-primary" style={{ width: `${Math.round(e.progress * 100)}%` }} />
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Async>
      </Card>

      {preview && <PlaybookPreview pb={preview} onClose={() => setPreview(null)} />}
      {execId && <PlaybookModal executionId={execId} onClose={() => setExecId(null)} onChanged={executions.refetch} />}
    </div>
  );
}
