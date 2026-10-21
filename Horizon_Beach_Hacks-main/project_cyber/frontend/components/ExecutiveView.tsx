"use client";

import { Bar, BarChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api } from "@/lib/api";
import { useQuery } from "@/hooks/useQuery";
import { Async, Card, fmtLakhs, titleCase } from "@/components/ui";

function Stat({ label, value, sub, tone }: { label: string; value: string; sub?: string; tone?: string }) {
  return (
    <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-md p-4">
      <p className="text-xs uppercase text-gray-500 dark:text-gray-300">{label}</p>
      <p className={`text-3xl font-bold ${tone ?? "text-gray-900 dark:text-white"}`}>{value}</p>
      {sub && <p className="text-xs text-gray-500 dark:text-gray-300 mt-1">{sub}</p>}
    </div>
  );
}

export default function ExecutiveView() {
  const q = useQuery(() => api.dashboard.executive(), [], 120000);
  return (
    <Async q={q}>
      {(e) => {
        const ch = e.control_health;
        const trendTone = e.risk_trend.label === "Rising" ? "text-critical" : e.risk_trend.label === "Falling" ? "text-success" : "text-gray-900 dark:text-white";
        return (
          <div className="space-y-3">
            <div className="grid grid-cols-2 xl:grid-cols-4 gap-3">
              <Stat label="Business risk score" value={`${e.business_risk_score} / 10`} />
              <Stat label="Expected financial exposure" value={fmtLakhs(e.financial_exposure_lakhs)} tone="text-critical" sub="probability-weighted loss" />
              <Stat label="7-day trend" value={e.risk_trend.label} tone={trendTone} sub={`${e.risk_trend.delta_7d > 0 ? "+" : ""}${e.risk_trend.delta_7d} avg BWVS`} />
              <Stat label={`Critical SLA breaches (>${ch.critical_sla_days}d)`} value={String(ch.critical_sla_breaches)} tone={ch.critical_sla_breaches ? "text-critical" : "text-success"} />
            </div>

            <div className="grid grid-cols-1 xl:grid-cols-2 gap-3">
              <Card title="Exposure by business unit (₹ lakhs)">
                {e.exposure_by_business_unit.length === 0 ? (
                  <p className="text-sm text-gray-500 dark:text-gray-300">No quantified exposure yet.</p>
                ) : (
                  <ResponsiveContainer width="100%" height={240}>
                    <BarChart data={e.exposure_by_business_unit} layout="vertical" margin={{ left: 20 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#E5E7EB" />
                      <XAxis type="number" tick={{ fontSize: 10 }} />
                      <YAxis type="category" dataKey="name" tick={{ fontSize: 11 }} width={110} />
                      <Tooltip formatter={(v: number) => fmtLakhs(v)} />
                      <Bar dataKey="lakhs" fill="#DC2626" radius={[0, 3, 3, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                )}
              </Card>
              <Card title="Monthly risk trend">
                {e.monthly_trend.length < 2 ? (
                  <p className="text-sm text-gray-500 dark:text-gray-300">Monthly history accumulates as risk snapshots are recorded.</p>
                ) : (
                  <ResponsiveContainer width="100%" height={240}>
                    <LineChart data={e.monthly_trend}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#E5E7EB" />
                      <XAxis dataKey="month" tick={{ fontSize: 10 }} />
                      <YAxis yAxisId="l" tick={{ fontSize: 10 }} domain={[0, 10]} />
                      <YAxis yAxisId="r" orientation="right" tick={{ fontSize: 10 }} />
                      <Tooltip />
                      <Line yAxisId="l" type="monotone" dataKey="risk_score_10" name="Risk score /10" stroke="#2563EB" />
                      <Line yAxisId="r" type="monotone" dataKey="exposure_lakhs" name="Exposure ₹L" stroke="#DC2626" />
                    </LineChart>
                  </ResponsiveContainer>
                )}
              </Card>
            </div>

            <div className="grid grid-cols-1 xl:grid-cols-2 gap-3">
              <Card title="Most exposed assets">
                {e.top_exposed_assets.length === 0 ? (
                  <p className="text-sm text-gray-500 dark:text-gray-300">No exposed assets.</p>
                ) : (
                  <table className="w-full text-sm">
                    <thead><tr className="text-left text-xs uppercase text-gray-500 dark:text-gray-300"><th className="py-1">Asset</th><th>Unit</th><th>P(loss)</th><th className="text-right">Expected loss</th></tr></thead>
                    <tbody>
                      {e.top_exposed_assets.map((a) => (
                        <tr key={a.asset_id} className="border-t border-gray-100 dark:border-gray-700 text-gray-800 dark:text-gray-100">
                          <td className="py-1.5">{a.asset_name}</td>
                          <td>{a.business_unit ?? "—"}</td>
                          <td>{(a.probability * 100).toFixed(0)}%</td>
                          <td className="text-right font-medium">{fmtLakhs(a.expected_loss_lakhs)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </Card>
              <Card title="Control health">
                <dl className="grid grid-cols-2 gap-3 text-sm text-gray-800 dark:text-gray-100">
                  <div><dt className="text-xs text-gray-500 dark:text-gray-300">Actively exploited (KEV) open</dt><dd className="text-xl font-bold">{ch.kev_open}</dd></div>
                  <div><dt className="text-xs text-gray-500 dark:text-gray-300">Internet-facing with serious risk</dt><dd className="text-xl font-bold">{ch.internet_facing_assets_with_serious_risk}</dd></div>
                  <div><dt className="text-xs text-gray-500 dark:text-gray-300">Risks opened / resolved (30d)</dt><dd className="text-xl font-bold">{ch.risks_opened_30d} / {ch.risks_resolved_30d}</dd></div>
                  <div><dt className="text-xs text-gray-500 dark:text-gray-300">Mean days to resolve</dt><dd className="text-xl font-bold">{ch.mean_days_to_resolve ?? "—"}</dd></div>
                </dl>
                {e.exposure_by_category.length > 0 && (
                  <p className="text-xs text-gray-500 dark:text-gray-300 mt-3">
                    By category: {e.exposure_by_category.map((c) => `${titleCase(c.name)} ${fmtLakhs(c.lakhs)}`).join(" · ")}
                  </p>
                )}
              </Card>
            </div>

            <Card title="Methodology & assumptions">
              <ul className="list-disc list-inside text-xs text-gray-600 dark:text-gray-300 space-y-1">
                {e.assumptions.map((a, i) => <li key={i}>{a}</li>)}
              </ul>
            </Card>
          </div>
        );
      }}
    </Async>
  );
}
