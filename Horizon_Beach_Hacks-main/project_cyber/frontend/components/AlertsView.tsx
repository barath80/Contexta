"use client";

import { useEffect, useState } from "react";
import { api, type Alert } from "@/lib/api";
import { useAction, useQuery } from "@/hooks/useQuery";
import { useAuth } from "@/contexts/AuthContext";
import { Async, Button, Card, LevelBadge, Modal, inputClass, fmtDate, timeAgo, titleCase } from "@/components/ui";
import Pager from "@/components/Pager";

const PAGE_SIZE = 25;
const CATEGORIES = ["login_failure", "port_scan", "malware_alert", "privilege_escalation", "data_exfiltration", "brute_force", "anomaly"];

export default function AlertsView({ initialQuery = "" }: { initialQuery?: string }) {
  const { can } = useAuth();
  const [q, setQ] = useState(initialQuery);
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("new");
  const [category, setCategory] = useState("");
  const [page, setPage] = useState(1);
  const [detail, setDetail] = useState<Alert | null>(null);

  const stats = useQuery(() => api.alerts.stats(24), [], 60000);
  const list = useQuery(
    () => api.alerts.list({ page, page_size: PAGE_SIZE, min_severity: severity, status, category, q: q.trim() }),
    [page, severity, status, category, q],
    15000,
  );
  const ack = useAction((id: string) => api.alerts.acknowledge(id));
  const dismiss = useAction((id: string) => api.alerts.dismiss(id));

  // Viewing the feed marks it as seen (clears the nav badge).
  useEffect(() => {
    api.alerts.markSeen().catch(() => undefined);
  }, []);

  const act = async (fn: (id: string) => Promise<unknown>, id: string) => {
    if (await fn(id)) {
      setDetail(null);
      list.refetch();
      stats.refetch();
    }
  };
  const filter = <T,>(set: (v: T) => void) => (v: T) => {
    set(v);
    setPage(1);
  };

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-md p-3">
          <p className="text-xs uppercase text-gray-500 dark:text-gray-300">Events (24h)</p>
          <p className="text-2xl font-bold text-gray-900 dark:text-white">{stats.data?.total ?? "—"}</p>
        </div>
        {(["critical", "high", "medium", "low"] as const).map((s) => (
          <div key={s} className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-md p-3">
            <p className="text-xs uppercase text-gray-500 dark:text-gray-300">{s}</p>
            <p className="text-2xl font-bold text-gray-900 dark:text-white">{stats.data?.by_severity[s] ?? 0}</p>
          </div>
        ))}
      </div>

      <Card title="Security events">
        <div className="flex flex-wrap gap-2 mb-3">
          <input value={q} onChange={(e) => filter(setQ)(e.target.value)} placeholder="Search message / IP / user…" aria-label="Search events" className={`${inputClass} !w-64`} />
          <select value={severity} onChange={(e) => filter(setSeverity)(e.target.value)} aria-label="Minimum severity" className={`${inputClass} !w-auto`}>
            <option value="">Any severity</option>
            {["critical", "high", "medium", "low"].map((s) => <option key={s} value={s}>≥ {s}</option>)}
          </select>
          <select value={status} onChange={(e) => filter(setStatus)(e.target.value)} aria-label="Status" className={`${inputClass} !w-auto`}>
            <option value="">Any status</option>
            {["new", "acknowledged", "dismissed"].map((s) => <option key={s} value={s}>{titleCase(s)}</option>)}
          </select>
          <select value={category} onChange={(e) => filter(setCategory)(e.target.value)} aria-label="Category" className={`${inputClass} !w-auto`}>
            <option value="">Any category</option>
            {CATEGORIES.map((c) => <option key={c} value={c}>{titleCase(c)}</option>)}
          </select>
        </div>
        <Async
          q={list}
          empty={{
            when: (d) => d.total === 0,
            title: "No events",
            hint: "Connect your SIEM or log shipper to POST /api/v1/logs/ingest (X-API-Key header) to see security events here.",
          }}
        >
          {(d) => (
            <>
              <ul className="divide-y divide-gray-100 dark:divide-gray-700">
                {d.items.map((a) => (
                  <li key={a.id} className="py-2 flex items-start gap-3">
                    <LevelBadge level={a.severity} />
                    <button onClick={() => setDetail(a)} className="flex-1 min-w-0 text-left">
                      <p className="text-sm text-gray-900 dark:text-white truncate">{a.message}</p>
                      <p className="text-xs text-gray-500 dark:text-gray-300 truncate">
                        {titleCase(a.category)} · {a.source}
                        {a.asset_name && ` · ${a.asset_name}`}
                        {a.source_ip && ` · from ${a.source_ip}`} · {timeAgo(a.created_at)}
                      </p>
                    </button>
                    {can("analyst") && a.status === "new" && (
                      <div className="flex gap-1.5 shrink-0">
                        <Button variant="secondary" disabled={ack.pending} onClick={() => act(ack.run, a.id)}>Acknowledge</Button>
                        <Button variant="secondary" disabled={dismiss.pending} onClick={() => act(dismiss.run, a.id)}>Dismiss</Button>
                      </div>
                    )}
                    {a.status !== "new" && <span className="text-xs text-gray-500 dark:text-gray-300 capitalize">{a.status}</span>}
                  </li>
                ))}
              </ul>
              <Pager page={page} pageSize={PAGE_SIZE} total={d.total} onPage={setPage} />
            </>
          )}
        </Async>
        {(ack.error || dismiss.error) && <p className="text-sm text-critical mt-2" role="alert">{ack.error || dismiss.error}</p>}
      </Card>

      {detail && (
        <Modal title="Event details" onClose={() => setDetail(null)}>
          <div className="space-y-3 text-sm text-gray-800 dark:text-gray-100">
            <div className="flex items-center gap-2"><LevelBadge level={detail.severity} /> <span>{titleCase(detail.category)}</span> <span className="text-xs text-gray-500">{fmtDate(detail.created_at)}</span></div>
            <p>{detail.message}</p>
            <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
              {([
                ["Source", detail.source], ["Asset", detail.asset_name], ["Source IP", detail.source_ip],
                ["Destination IP", detail.destination_ip], ["Destination port", detail.destination_port], ["User", detail.username],
              ] as const).map(([k, v]) => v !== null && v !== undefined && v !== "" && (
                <div key={k}><dt className="text-gray-500 dark:text-gray-400">{k}</dt><dd className="font-medium">{String(v)}</dd></div>
              ))}
            </dl>
            {Object.keys(detail.raw_log).length > 0 && (
              <pre className="text-xs bg-gray-100 dark:bg-gray-900 p-3 rounded overflow-auto max-h-60">{JSON.stringify(detail.raw_log, null, 2)}</pre>
            )}
          </div>
        </Modal>
      )}
    </div>
  );
}
