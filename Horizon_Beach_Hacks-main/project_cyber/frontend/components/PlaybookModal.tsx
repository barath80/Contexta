"use client";

import { useState } from "react";
import { CheckCircle2, Circle, Loader2, SkipForward, XCircle, Hand, Cog } from "lucide-react";
import { api, type PlaybookExecution } from "@/lib/api";
import { useAction, useQuery } from "@/hooks/useQuery";
import { useAuth } from "@/contexts/AuthContext";
import { Async, Button, Modal, inputClass, timeAgo } from "@/components/ui";

const STEP_ICON: Record<string, React.ReactElement> = {
  completed: <CheckCircle2 className="w-5 h-5 text-success" />,
  skipped: <SkipForward className="w-5 h-5 text-gray-400" />,
  failed: <XCircle className="w-5 h-5 text-critical" />,
  awaiting: <Hand className="w-5 h-5 text-warning" />,
  pending: <Circle className="w-5 h-5 text-gray-300" />,
};

/** Live view of a playbook execution: automated steps run server-side, manual steps wait for the analyst. */
export default function PlaybookModal({
  executionId,
  onClose,
  onChanged,
}: {
  executionId: string;
  onClose: () => void;
  onChanged?: () => void;
}) {
  const { can } = useAuth();
  const [notes, setNotes] = useState("");
  const q = useQuery(() => api.playbooks.execution(executionId), [executionId], 5000);
  const complete = useAction((ex: PlaybookExecution, order: number) => api.playbooks.completeStep(ex.id, order, notes || undefined));
  const skip = useAction((ex: PlaybookExecution, order: number) => api.playbooks.skipStep(ex.id, order, notes || undefined));
  const cancel = useAction((ex: PlaybookExecution) => api.playbooks.cancel(ex.id));

  const after = async () => {
    setNotes("");
    await q.refetch();
    onChanged?.();
  };
  const busy = complete.pending || skip.pending || cancel.pending;
  const error = complete.error || skip.error || cancel.error;

  return (
    <Modal title="Playbook execution" onClose={onClose} wide>
      <Async q={q}>
        {(ex) => (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <p className="font-semibold text-gray-900 dark:text-white">{ex.playbook_name}</p>
                <p className="text-xs text-gray-500 dark:text-gray-300">
                  {ex.risk_title ? `For: ${ex.risk_title} · ` : ""}Started {timeAgo(ex.started_at)}
                </p>
              </div>
              <span className="text-xs font-semibold uppercase px-2 py-1 rounded bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-white">
                {ex.status}
              </span>
            </div>

            <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden" aria-label="Progress">
              <div className="h-full bg-primary transition-all" style={{ width: `${Math.round(ex.progress * 100)}%` }} />
            </div>

            {ex.error_message && <p className="text-sm text-critical">{ex.error_message}</p>}

            <ol className="space-y-2">
              {ex.step_results.map((s) => (
                <li key={s.order} className="flex gap-3 p-3 rounded-md border border-gray-200 dark:border-gray-700">
                  <div className="pt-0.5">{STEP_ICON[s.status] ?? STEP_ICON.pending}</div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-gray-900 dark:text-white flex items-center gap-2">
                      {s.order}. {s.name}
                      <span className="inline-flex items-center gap-1 text-xs text-gray-500 dark:text-gray-300">
                        {s.action_type === "automated" ? <Cog className="w-3 h-3" /> : <Hand className="w-3 h-3" />}
                        {s.action_type}
                      </span>
                    </p>
                    {"description" in s && typeof (s as Record<string, unknown>).description === "string" && (
                      <p className="text-xs text-gray-600 dark:text-gray-300 mt-0.5">{(s as Record<string, unknown>).description as string}</p>
                    )}
                    {s.notes && <p className="text-xs italic text-gray-500 dark:text-gray-300 mt-1">“{s.notes}”</p>}
                    {s.error && <p className="text-xs text-critical mt-1">{s.error}</p>}
                    {s.status === "awaiting" && ex.status === "running" && can("analyst") && (
                      <div className="mt-2 space-y-2">
                        <input
                          value={notes}
                          onChange={(e) => setNotes(e.target.value)}
                          placeholder="Notes (optional)"
                          className={inputClass}
                          maxLength={2000}
                        />
                        <div className="flex gap-2">
                          <Button disabled={busy} onClick={async () => { await complete.run(ex, s.order); await after(); }}>
                            {complete.pending && <Loader2 className="w-3 h-3 animate-spin" />} Mark done
                          </Button>
                          <Button variant="secondary" disabled={busy} onClick={async () => { await skip.run(ex, s.order); await after(); }}>
                            Skip
                          </Button>
                        </div>
                      </div>
                    )}
                  </div>
                </li>
              ))}
            </ol>

            {error && <p className="text-sm text-critical" role="alert">{error}</p>}

            {ex.status === "running" && can("analyst") && (
              <div className="flex justify-end">
                <Button variant="danger" disabled={busy} onClick={async () => { await cancel.run(ex); await after(); }}>
                  Cancel execution
                </Button>
              </div>
            )}
          </div>
        )}
      </Async>
    </Modal>
  );
}
