"use client";

import { useState } from "react";
import { api } from "@/lib/api";
import { useQuery } from "@/hooks/useQuery";
import { Async, Card, LevelBadge, inputClass, timeAgo, titleCase } from "@/components/ui";
import Pager from "@/components/Pager";
import RiskDetailModal from "@/components/RiskDetailModal";

const PAGE_SIZE = 25;

export default function RisksView({ initialQuery = "" }: { initialQuery?: string }) {
  const [q, setQ] = useState(initialQuery);
  const [level, setLevel] = useState("");
  const [status, setStatus] = useState("");
  const [openOnly, setOpenOnly] = useState(true);
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<string | null>(null);

  const stats = useQuery(() => api.risks.stats(), [], 60000);
  const list = useQuery(
    () => api.risks.list({ page, page_size: PAGE_SIZE, level, status, q: q.trim(), open_only: openOnly && !status ? true : undefined }),
    [page, level, status, q, openOnly],
    60000,
  );

  const reset = <T,>(set: (v: T) => void) => (v: T) => {
    set(v);
    setPage(1);
  };

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {stats.data &&
          (["critical", "high", "medium", "low"] as const).map((l) => (
            <button
              key={l}
              onClick={() => reset(setLevel)(level === l ? "" : l)}
              className={`text-left bg-white dark:bg-gray-800 border rounded-md p-3 ${level === l ? "border-primary ring-1 ring-primary" : "border-gray-200 dark:border-gray-700"}`}
            >
              <p className="text-xs uppercase text-gray-500 dark:text-gray-300">{l}</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">{stats.data!.by_level[l] ?? 0}</p>
            </button>
          ))}
        {stats.data && (
          <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-md p-3">
            <p className="text-xs uppercase text-gray-500 dark:text-gray-300">Actively exploited</p>
            <p className="text-2xl font-bold text-critical">{stats.data.kev_open}</p>
          </div>
        )}
      </div>

      <Card title="Risk register">
        <div className="flex flex-wrap gap-2 mb-3">
          <input
            value={q}
            onChange={(e) => reset(setQ)(e.target.value)}
            placeholder="Search risks…"
            aria-label="Search risks"
            className={`${inputClass} !w-64`}
          />
          <select value={status} onChange={(e) => reset(setStatus)(e.target.value)} aria-label="Status" className={`${inputClass} !w-auto`}>
            <option value="">Any status</option>
            {["active", "investigating", "mitigating", "resolved", "accepted"].map((s) => (
              <option key={s} value={s}>{titleCase(s)}</option>
            ))}
          </select>
          <label className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-200">
            <input type="checkbox" checked={openOnly} disabled={!!status} onChange={(e) => reset(setOpenOnly)(e.target.checked)} /> Open only
          </label>
        </div>
        <Async q={list} empty={{ when: (d) => d.total === 0, title: "No risks match", hint: "Adjust the filters, or add assets and wait for the threat feeds to sync." }}>
          {(d) => (
            <>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-left text-xs uppercase text-gray-500 dark:text-gray-300 border-b border-gray-200 dark:border-gray-700">
                      <th className="py-2 pr-3">Risk</th>
                      <th className="py-2 pr-3">Asset</th>
                      <th className="py-2 pr-3">BWVS</th>
                      <th className="py-2 pr-3">Level</th>
                      <th className="py-2 pr-3">Status</th>
                      <th className="py-2">Last seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {d.items.map((r) => (
                      <tr
                        key={r.id}
                        onClick={() => setSelected(r.id)}
                        className="border-b border-gray-100 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700/50 cursor-pointer"
                      >
                        <td className="py-2 pr-3 max-w-md">
                          <p className="font-medium text-gray-900 dark:text-white truncate">{r.title}</p>
                          <p className="text-xs text-gray-500 dark:text-gray-300">
                            {r.cve?.cve_id}
                            {r.cve?.cisa_kev && " · KEV"}
                          </p>
                        </td>
                        <td className="py-2 pr-3 text-gray-700 dark:text-gray-200">{r.asset?.name ?? "—"}</td>
                        <td className="py-2 pr-3 font-bold text-gray-900 dark:text-white">{r.bwvs_score.toFixed(0)}</td>
                        <td className="py-2 pr-3"><LevelBadge level={r.level} /></td>
                        <td className="py-2 pr-3 text-gray-700 dark:text-gray-200">{titleCase(r.status)}</td>
                        <td className="py-2 text-gray-500 dark:text-gray-300">{timeAgo(r.last_seen)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <Pager page={page} pageSize={PAGE_SIZE} total={d.total} onPage={setPage} />
            </>
          )}
        </Async>
      </Card>
      {selected && (
        <RiskDetailModal
          riskId={selected}
          onClose={() => setSelected(null)}
          onChanged={() => {
            list.refetch();
            stats.refetch();
          }}
        />
      )}
    </div>
  );
}
