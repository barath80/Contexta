"use client";

import { useState } from "react";
import { Download, FileText } from "lucide-react";
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api, type Analytics } from "@/lib/api";
import { useAction, useQuery } from "@/hooks/useQuery";
import { useAuth } from "@/contexts/AuthContext";
import { Async, Button, Card, LevelBadge, Modal, fmtDate, titleCase } from "@/components/ui";

const CATEGORY_COLORS = ["#DC2626", "#F59E0B", "#3B82F6", "#16A34A", "#8B5CF6", "#0EA5E9", "#64748B"];

/** Minimal Markdown (headings, bullets, bold) for generated reports. */
function Markdown({ text }: { text: string }) {
  const inline = (s: string) =>
    s.split(/(\*\*[^*]+\*\*)/g).map((part, i) =>
      part.startsWith("**") && part.endsWith("**") ? <strong key={i}>{part.slice(2, -2)}</strong> : <span key={i}>{part}</span>,
    );
  return (
    <div className="space-y-1.5 text-sm text-gray-800 dark:text-gray-100">
      {text.split("\n").map((line, i) => {
        if (line.startsWith("### ")) return <h4 key={i} className="font-semibold mt-3">{inline(line.slice(4))}</h4>;
        if (line.startsWith("## ")) return <h3 key={i} className="text-base font-semibold mt-4">{inline(line.slice(3))}</h3>;
        if (line.startsWith("# ")) return <h2 key={i} className="text-lg font-bold">{inline(line.slice(2))}</h2>;
        if (/^\s*[-*] /.test(line)) return <p key={i} className="pl-4">• {inline(line.replace(/^\s*[-*] /, ""))}</p>;
        if (line.trim() === "---") return <hr key={i} className="border-gray-200 dark:border-gray-700 my-2" />;
        return line.trim() ? <p key={i}>{inline(line)}</p> : null;
      })}
    </div>
  );
}

function exportCsv(a: Analytics) {
  const esc = (v: unknown) => `"${String(v ?? "").replace(/"/g, '""')}"`;
  const rows = [["Title", "BWVS", "Priority", "Level", "Asset", "CVE"], ...a.top_risks.map((r) => [r.title, r.bwvs, r.priority, r.level, r.asset, r.cve])];
  const blob = new Blob([rows.map((r) => r.map(esc).join(",")).join("\n")], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `contexta-top-risks-${new Date().toISOString().slice(0, 10)}.csv`;
  link.click();
  URL.revokeObjectURL(url);
}

export default function ReportsView() {
  const { can } = useAuth();
  const analytics = useQuery(() => api.reports.analytics(6, 6), [], 120000);
  const reports = useQuery(() => api.reports.list(), []);
  const [openId, setOpenId] = useState<string | null>(null);
  const opened = useQuery(() => (openId ? api.reports.get(openId) : Promise.resolve(null)), [openId]);
  const generate = useAction(() => api.reports.generateBoard());

  return (
    <div className="space-y-3">
      <Async q={analytics}>
        {(a) => {
          const k = a.kpis;
          const categories = Array.from(new Set(a.threat_activity.flatMap((w) => Object.keys(w).filter((x) => x !== "week"))));
          return (
            <>
              <div className="grid grid-cols-2 xl:grid-cols-4 gap-3">
                {([
                  ["Incidents (total)", k.incidents_total], ["Resolved", k.incidents_resolved_pct === null ? "—" : `${k.incidents_resolved_pct}%`],
                  ["Mean time to resolve", k.mean_time_to_resolve_hours === null ? "—" : `${k.mean_time_to_resolve_hours}h`], ["Events processed", k.events_processed.toLocaleString()],
                  ["Open risks", k.open_risks], ["Critical risks", k.critical_risks], ["Risks resolved", k.risks_resolved], ["Average BWVS", k.average_bwvs],
                ] as const).map(([label, v]) => (
                  <div key={label} className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-md p-3">
                    <p className="text-xs uppercase text-gray-500 dark:text-gray-300">{label}</p>
                    <p className="text-2xl font-bold text-gray-900 dark:text-white">{v}</p>
                  </div>
                ))}
              </div>
              <div className="grid grid-cols-1 xl:grid-cols-2 gap-3">
                <Card title="Incidents per month">
                  <ResponsiveContainer width="100%" height={220}>
                    <BarChart data={a.monthly_incidents}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#E5E7EB" />
                      <XAxis dataKey="month" tick={{ fontSize: 10 }} /><YAxis allowDecimals={false} tick={{ fontSize: 10 }} />
                      <Tooltip /><Legend wrapperStyle={{ fontSize: 11 }} />
                      <Bar dataKey="resolved" stackId="a" fill="#16A34A" /><Bar dataKey="pending" stackId="a" fill="#F59E0B" />
                    </BarChart>
                  </ResponsiveContainer>
                </Card>
                <Card title="Threat activity per week (events by category)">
                  {categories.length === 0 ? (
                    <p className="text-sm text-gray-500 dark:text-gray-300">No security events ingested in this period.</p>
                  ) : (
                    <ResponsiveContainer width="100%" height={220}>
                      <BarChart data={a.threat_activity}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#E5E7EB" />
                        <XAxis dataKey="week" tick={{ fontSize: 10 }} /><YAxis allowDecimals={false} tick={{ fontSize: 10 }} />
                        <Tooltip /><Legend wrapperStyle={{ fontSize: 10 }} />
                        {categories.map((c, i) => <Bar key={c} dataKey={c} name={titleCase(c)} stackId="a" fill={CATEGORY_COLORS[i % CATEGORY_COLORS.length]} />)}
                      </BarChart>
                    </ResponsiveContainer>
                  )}
                </Card>
              </div>
              <Card title="Top 10 risks" action={<Button variant="secondary" onClick={() => exportCsv(a)}><Download className="w-4 h-4" /> Export CSV</Button>}>
                <table className="w-full text-sm">
                  <thead><tr className="text-left text-xs uppercase text-gray-500 dark:text-gray-300"><th className="py-1">Risk</th><th>Asset</th><th>BWVS</th><th>Level</th></tr></thead>
                  <tbody>
                    {a.top_risks.map((r, i) => (
                      <tr key={i} className="border-t border-gray-100 dark:border-gray-700 text-gray-800 dark:text-gray-100">
                        <td className="py-1.5 pr-3 max-w-md truncate">{r.title}</td><td>{r.asset ?? "—"}</td>
                        <td className="font-bold">{r.bwvs.toFixed(0)}</td><td><LevelBadge level={r.level} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <p className="text-xs text-gray-500 dark:text-gray-300 mt-2">Generated {fmtDate(a.generated_at)}</p>
              </Card>
            </>
          );
        }}
      </Async>

      <Card
        title="Board reports"
        action={can("analyst") && (
          <Button
            disabled={generate.pending}
            onClick={async () => {
              const r = await generate.run();
              if (r) {
                await reports.refetch();
                setOpenId(r.id);
              }
            }}
          >
            <FileText className="w-4 h-4" /> {generate.pending ? "Generating…" : "Generate board report"}
          </Button>
        )}
      >
        {generate.error && <p className="text-sm text-critical mb-2" role="alert">{generate.error}</p>}
        <Async q={reports} empty={{ when: (d) => d.length === 0, title: "No reports yet", hint: "Generate a board report from the current executive metrics." }}>
          {(list) => (
            <ul className="divide-y divide-gray-100 dark:divide-gray-700">
              {list.map((r) => (
                <li key={r.id}>
                  <button onClick={() => setOpenId(r.id)} className="w-full text-left py-2 flex justify-between gap-3 hover:bg-gray-50 dark:hover:bg-gray-700/50 px-1 rounded">
                    <span className="text-sm font-medium text-gray-900 dark:text-white">{r.title}</span>
                    <span className="text-xs text-gray-500 dark:text-gray-300">{fmtDate(r.created_at)} · {r.generated_by}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Async>
      </Card>

      {openId && (
        <Modal wide title={opened.data?.title ?? "Report"} onClose={() => setOpenId(null)}>
          <Async q={opened}>{(r) => (r ? <Markdown text={r.content ?? ""} /> : null)}</Async>
        </Modal>
      )}
    </div>
  );
}
