"use client";

import { useState } from "react";
import { Plus, ShieldOff, ShieldCheck, Trash2, Upload } from "lucide-react";
import { api, type Asset, type AssetInput } from "@/lib/api";
import { useAction, useQuery } from "@/hooks/useQuery";
import { useAuth } from "@/contexts/AuthContext";
import { Async, Button, Card, LevelBadge, Modal, fmtLakhs, inputClass, titleCase } from "@/components/ui";
import Pager from "@/components/Pager";

const PAGE_SIZE = 25;
const TYPES = ["server", "workstation", "network_device", "database", "application", "cloud_service", "iot_device"];
const EXPOSURES = ["internet_facing", "vpn", "internal", "isolated"];
const CRITICALITIES = ["payment_payroll", "core_backend", "crm_hr", "dev_test"];
const ZONES = ["external", "dmz", "internal", "restricted", "cloud"];

const blank = (): AssetInput => ({
  name: "", asset_type: "server", hostname: "", ip_address: "", os: "", software: [],
  exposure_level: "internal", criticality: "dev_test", network_zone: "internal",
  business_unit: "", owner: "", location: "", daily_revenue_impact: 0,
});

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block text-sm">
      <span className="block mb-1 text-gray-700 dark:text-gray-200">{label}</span>
      {children}
    </label>
  );
}

function AssetForm({ initial, onClose, onSaved }: { initial?: Asset; onClose: () => void; onSaved: () => void }) {
  const [f, setF] = useState<AssetInput>(initial ? { ...initial } : blank());
  const [software, setSoftware] = useState((initial?.software ?? []).join("\n"));
  const save = useAction(async () => {
    // Empty strings become null so optional fields stay clean.
    const clean = (v?: string | null) => (v && v.trim() ? v.trim() : null);
    const body: AssetInput = {
      name: f.name.trim(), asset_type: f.asset_type, hostname: clean(f.hostname), ip_address: clean(f.ip_address), os: clean(f.os),
      software: software.split("\n").map((s) => s.trim()).filter(Boolean), exposure_level: f.exposure_level, criticality: f.criticality,
      network_zone: f.network_zone, business_unit: clean(f.business_unit), owner: clean(f.owner), location: clean(f.location),
      daily_revenue_impact: Number(f.daily_revenue_impact) || 0,
    };
    return initial ? api.assets.update(initial.id, body) : api.assets.create(body);
  });
  const set = (k: keyof AssetInput) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setF({ ...f, [k]: e.target.value });

  return (
    <Modal title={initial ? `Edit ${initial.name}` : "Add asset"} onClose={onClose} wide>
      <form
        className="grid sm:grid-cols-2 gap-3"
        onSubmit={async (e) => {
          e.preventDefault();
          if (await save.run()) {
            onSaved();
            onClose();
          }
        }}
      >
        <Field label="Name *"><input required className={inputClass} value={f.name} onChange={set("name")} maxLength={255} /></Field>
        <Field label="Type">
          <select className={inputClass} value={f.asset_type} onChange={set("asset_type")}>{TYPES.map((t) => <option key={t} value={t}>{titleCase(t)}</option>)}</select>
        </Field>
        <Field label="Hostname"><input className={inputClass} value={f.hostname ?? ""} onChange={set("hostname")} /></Field>
        <Field label="IP address"><input className={inputClass} value={f.ip_address ?? ""} onChange={set("ip_address")} /></Field>
        <Field label="Operating system"><input className={inputClass} value={f.os ?? ""} onChange={set("os")} placeholder="e.g. Ubuntu 22.04" /></Field>
        <Field label="Business unit"><input className={inputClass} value={f.business_unit ?? ""} onChange={set("business_unit")} /></Field>
        <Field label="Exposure">
          <select className={inputClass} value={f.exposure_level} onChange={set("exposure_level")}>{EXPOSURES.map((t) => <option key={t} value={t}>{titleCase(t)}</option>)}</select>
        </Field>
        <Field label="Business criticality">
          <select className={inputClass} value={f.criticality} onChange={set("criticality")}>{CRITICALITIES.map((t) => <option key={t} value={t}>{titleCase(t)}</option>)}</select>
        </Field>
        <Field label="Network zone">
          <select className={inputClass} value={f.network_zone} onChange={set("network_zone")}>{ZONES.map((t) => <option key={t} value={t}>{titleCase(t)}</option>)}</select>
        </Field>
        <Field label="Revenue impact (₹ lakhs / day of downtime)">
          <input type="number" min={0} step="0.1" className={inputClass} value={f.daily_revenue_impact ?? 0} onChange={set("daily_revenue_impact")} />
        </Field>
        <Field label="Owner"><input className={inputClass} value={f.owner ?? ""} onChange={set("owner")} /></Field>
        <Field label="Location"><input className={inputClass} value={f.location ?? ""} onChange={set("location")} /></Field>
        <div className="sm:col-span-2">
          <Field label="Installed software (one per line, e.g. “nginx 1.24.0”) — used to match CVEs">
            <textarea className={inputClass} rows={4} value={software} onChange={(e) => setSoftware(e.target.value)} />
          </Field>
        </div>
        {save.error && <p className="sm:col-span-2 text-sm text-critical" role="alert">{save.error}</p>}
        <div className="sm:col-span-2 flex justify-end gap-2">
          <Button variant="secondary" onClick={onClose}>Cancel</Button>
          <Button type="submit" disabled={save.pending || !f.name.trim()}>{save.pending ? "Saving…" : "Save asset"}</Button>
        </div>
      </form>
    </Modal>
  );
}

function ImportModal({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [text, setText] = useState("");
  const [result, setResult] = useState<string | null>(null);
  const run = useAction(async () => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new Error("That is not valid JSON.");
    }
    const assets = Array.isArray(parsed) ? parsed : (parsed as { assets?: unknown })?.assets;
    if (!Array.isArray(assets) || assets.length === 0) throw new Error("Provide a JSON array of assets, or {\"assets\": [...]}.");
    const r = await api.assets.import(assets as AssetInput[]);
    setResult(`Imported ${r.created} asset(s), skipped ${r.skipped.length}, created ${r.risks_created} risk(s).` + (r.skipped.length ? ` Skipped: ${r.skipped.map((s) => `${s.name} (${s.reason})`).join("; ")}` : ""));
    onDone();
  });
  return (
    <Modal title="Import assets (JSON)" onClose={onClose} wide>
      <p className="text-xs text-gray-600 dark:text-gray-300 mb-2">
        Each asset needs <code>name</code> and <code>asset_type</code>; optional fields: hostname, ip_address, os, software[], exposure_level, criticality, network_zone, business_unit, owner, location, daily_revenue_impact.
      </p>
      <input
        type="file"
        accept="application/json,.json"
        aria-label="Choose JSON file"
        className="text-sm mb-2"
        onChange={async (e) => { const file = e.target.files?.[0]; if (file) setText(await file.text()); }}
      />
      <textarea className={`${inputClass} font-mono text-xs`} rows={12} value={text} onChange={(e) => setText(e.target.value)} placeholder='[{"name":"Web 01","asset_type":"server","ip_address":"10.0.0.5","software":["nginx 1.24.0"]}]' />
      {run.error && <p className="text-sm text-critical mt-2" role="alert">{run.error}</p>}
      {result && <p className="text-sm text-success mt-2">{result}</p>}
      <div className="flex justify-end gap-2 mt-3">
        <Button variant="secondary" onClick={onClose}>Close</Button>
        <Button disabled={run.pending || !text.trim()} onClick={() => run.run()}>{run.pending ? "Importing…" : "Import"}</Button>
      </div>
    </Modal>
  );
}

export default function AssetsView({ initialQuery = "" }: { initialQuery?: string }) {
  const { can } = useAuth();
  const [q, setQ] = useState(initialQuery);
  const [type, setType] = useState("");
  const [criticality, setCriticality] = useState("");
  const [page, setPage] = useState(1);
  const [editing, setEditing] = useState<Asset | "new" | null>(null);
  const [importing, setImporting] = useState(false);

  const stats = useQuery(() => api.assets.stats(), [], 60000);
  const list = useQuery(
    () => api.assets.list({ page, page_size: PAGE_SIZE, asset_type: type, criticality, q: q.trim() }),
    [page, type, criticality, q],
    60000,
  );
  const refresh = () => { list.refetch(); stats.refetch(); };
  const toggleIso = useAction((a: Asset) => (a.is_isolated ? api.assets.restore(a.id) : api.assets.isolate(a.id)));
  const remove = useAction((a: Asset) => api.assets.remove(a.id));
  const filter = <T,>(set: (v: T) => void) => (v: T) => { set(v); setPage(1); };

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {([
          ["Total assets", stats.data?.total], ["Internet-facing", stats.data?.internet_facing],
          ["Business-critical", stats.data?.critical], ["Isolated", stats.data?.isolated],
        ] as const).map(([label, v]) => (
          <div key={label} className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-md p-3">
            <p className="text-xs uppercase text-gray-500 dark:text-gray-300">{label}</p>
            <p className="text-2xl font-bold text-gray-900 dark:text-white">{v ?? "—"}</p>
          </div>
        ))}
      </div>

      <Card
        title="Asset inventory"
        action={can("analyst") && (
          <div className="flex gap-2">
            <Button variant="secondary" onClick={() => setImporting(true)}><Upload className="w-4 h-4" /> Import</Button>
            <Button onClick={() => setEditing("new")}><Plus className="w-4 h-4" /> Add asset</Button>
          </div>
        )}
      >
        <div className="flex flex-wrap gap-2 mb-3">
          <input value={q} onChange={(e) => filter(setQ)(e.target.value)} placeholder="Search name / host / IP…" aria-label="Search assets" className={`${inputClass} !w-64`} />
          <select value={type} onChange={(e) => filter(setType)(e.target.value)} aria-label="Type" className={`${inputClass} !w-auto`}>
            <option value="">Any type</option>{TYPES.map((t) => <option key={t} value={t}>{titleCase(t)}</option>)}
          </select>
          <select value={criticality} onChange={(e) => filter(setCriticality)(e.target.value)} aria-label="Criticality" className={`${inputClass} !w-auto`}>
            <option value="">Any criticality</option>{CRITICALITIES.map((t) => <option key={t} value={t}>{titleCase(t)}</option>)}
          </select>
        </div>
        <Async
          q={list}
          empty={{
            when: (d) => d.total === 0,
            title: "No assets",
            hint: "Add the systems you run (with installed software) so Contexta can match them against live CVE feeds.",
          }}
        >
          {(d) => (
            <>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-left text-xs uppercase text-gray-500 dark:text-gray-300 border-b border-gray-200 dark:border-gray-700">
                      <th className="py-2 pr-3">Asset</th><th className="py-2 pr-3">Type</th><th className="py-2 pr-3">Exposure</th>
                      <th className="py-2 pr-3">Criticality</th><th className="py-2 pr-3">Revenue/day</th><th className="py-2 pr-3">Risk</th><th className="py-2" />
                    </tr>
                  </thead>
                  <tbody>
                    {d.items.map((a) => (
                      <tr key={a.id} className="border-b border-gray-100 dark:border-gray-700">
                        <td className="py-2 pr-3">
                          <p className="font-medium text-gray-900 dark:text-white">{a.name}{a.is_isolated && <span className="ml-2 text-xs text-warning">isolated</span>}</p>
                          <p className="text-xs text-gray-500 dark:text-gray-300">{[a.hostname, a.ip_address].filter(Boolean).join(" · ")}</p>
                        </td>
                        <td className="py-2 pr-3 text-gray-700 dark:text-gray-200">{titleCase(a.asset_type)}</td>
                        <td className="py-2 pr-3 text-gray-700 dark:text-gray-200">{titleCase(a.exposure_level)}</td>
                        <td className="py-2 pr-3 text-gray-700 dark:text-gray-200">{titleCase(a.criticality)}</td>
                        <td className="py-2 pr-3 text-gray-700 dark:text-gray-200">{fmtLakhs(a.daily_revenue_impact)}</td>
                        <td className="py-2 pr-3">
                          <LevelBadge level={a.risk_level} />
                          {a.open_risks > 0 && <span className="ml-2 text-xs text-gray-500 dark:text-gray-300">{a.open_risks} open</span>}
                        </td>
                        <td className="py-2 text-right whitespace-nowrap">
                          {can("analyst") && (
                            <>
                              <button className="text-primary text-xs mr-3 hover:underline" onClick={() => setEditing(a)}>Edit</button>
                              <button
                                title={a.is_isolated ? "Restore to network" : "Isolate from network"}
                                aria-label={a.is_isolated ? "Restore asset" : "Isolate asset"}
                                disabled={toggleIso.pending}
                                className="p-1 text-gray-600 dark:text-gray-200 hover:text-primary"
                                onClick={async () => { if (await toggleIso.run(a)) refresh(); }}
                              >
                                {a.is_isolated ? <ShieldCheck className="w-4 h-4" /> : <ShieldOff className="w-4 h-4" />}
                              </button>
                            </>
                          )}
                          {can("admin") && (
                            <button
                              aria-label="Delete asset"
                              title="Delete"
                              className="p-1 text-gray-600 dark:text-gray-200 hover:text-critical"
                              onClick={async () => {
                                if (window.confirm(`Delete ${a.name}? Its risks and connections are removed too.`) && (await remove.run(a)) !== undefined) refresh();
                              }}
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <Pager page={page} pageSize={PAGE_SIZE} total={d.total} onPage={setPage} />
            </>
          )}
        </Async>
        {(toggleIso.error || remove.error) && <p className="text-sm text-critical mt-2" role="alert">{toggleIso.error || remove.error}</p>}
      </Card>

      {editing && <AssetForm initial={editing === "new" ? undefined : editing} onClose={() => setEditing(null)} onSaved={refresh} />}
      {importing && <ImportModal onClose={() => setImporting(false)} onDone={refresh} />}
    </div>
  );
}
