"use client";

import { useEffect, useState } from "react";
import { api, type OrganizationSettings, type Role, type User } from "@/lib/api";
import { useAction, useQuery } from "@/hooks/useQuery";
import { useAuth } from "@/contexts/AuthContext";
import { useTheme } from "@/contexts/ThemeContext";
import { Async, Button, Card, inputClass, fmtDate, timeAgo, titleCase } from "@/components/ui";

type Tab = "profile" | "organization" | "integrations" | "users" | "system";

function Saved({ ok }: { ok: boolean }) {
  return ok ? <span className="text-sm text-success" role="status">Saved</span> : null;
}

function Profile() {
  const { user, refreshUser } = useAuth();
  const { theme, setTheme } = useTheme();
  const [name, setName] = useState(user?.full_name ?? "");
  const [minSev, setMinSev] = useState(String(user?.preferences?.alert_min_severity ?? "high"));
  const [saved, setSaved] = useState(false);
  const save = useAction(async () => {
    await api.auth.updateMe({ full_name: name, preferences: { alert_min_severity: minSev, theme } });
    await refreshUser();
    setSaved(true);
  });
  const [cur, setCur] = useState("");
  const [next, setNext] = useState("");
  const [pwMsg, setPwMsg] = useState<string | null>(null);
  const change = useAction(async () => {
    const r = await api.auth.changePassword(cur, next);
    setPwMsg(r.message);
    setCur("");
    setNext("");
  });

  return (
    <div className="grid xl:grid-cols-2 gap-3">
      <Card title="Profile & preferences">
        <form className="space-y-3 max-w-md" onSubmit={async (e) => { e.preventDefault(); setSaved(false); await save.run(); }}>
          <label className="block text-sm"><span className="block mb-1 text-gray-700 dark:text-gray-200">Email</span><input className={inputClass} value={user?.email ?? ""} disabled /></label>
          <label className="block text-sm"><span className="block mb-1 text-gray-700 dark:text-gray-200">Full name</span><input className={inputClass} value={name} onChange={(e) => setName(e.target.value)} maxLength={255} /></label>
          <label className="block text-sm">
            <span className="block mb-1 text-gray-700 dark:text-gray-200">Theme</span>
            <select className={inputClass} value={theme} onChange={(e) => setTheme(e.target.value as "light" | "dark" | "auto")}>
              <option value="light">Light</option><option value="dark">Dark</option><option value="auto">Match system</option>
            </select>
          </label>
          <label className="block text-sm">
            <span className="block mb-1 text-gray-700 dark:text-gray-200">Notify me about alerts of at least</span>
            <select className={inputClass} value={minSev} onChange={(e) => setMinSev(e.target.value)}>
              {["critical", "high", "medium", "low"].map((s) => <option key={s} value={s}>{titleCase(s)}</option>)}
            </select>
          </label>
          {save.error && <p className="text-sm text-critical" role="alert">{save.error}</p>}
          <div className="flex items-center gap-3"><Button type="submit" disabled={save.pending}>Save</Button><Saved ok={saved} /></div>
        </form>
      </Card>
      <Card title="Change password">
        <form className="space-y-3 max-w-md" onSubmit={async (e) => { e.preventDefault(); setPwMsg(null); await change.run(); }}>
          <label className="block text-sm"><span className="block mb-1 text-gray-700 dark:text-gray-200">Current password</span><input type="password" autoComplete="current-password" className={inputClass} value={cur} onChange={(e) => setCur(e.target.value)} required /></label>
          <label className="block text-sm"><span className="block mb-1 text-gray-700 dark:text-gray-200">New password (min. 10 characters)</span><input type="password" autoComplete="new-password" minLength={10} className={inputClass} value={next} onChange={(e) => setNext(e.target.value)} required /></label>
          {change.error && <p className="text-sm text-critical" role="alert">{change.error}</p>}
          {pwMsg && <p className="text-sm text-success" role="status">{pwMsg}</p>}
          <Button type="submit" disabled={change.pending}>Change password</Button>
        </form>
      </Card>
    </div>
  );
}

function Organization() {
  const q = useQuery(() => api.settings.organization(), []);
  const [f, setF] = useState<OrganizationSettings | null>(null);
  const [frameworks, setFrameworks] = useState("");
  const [saved, setSaved] = useState(false);
  useEffect(() => {
    if (q.data) {
      setF(q.data);
      setFrameworks(q.data.compliance_frameworks.join(", "));
    }
  }, [q.data]);
  const { can } = useAuth();
  const save = useAction(async () => {
    await api.settings.saveOrganization({ ...f!, compliance_frameworks: frameworks.split(",").map((s) => s.trim()).filter(Boolean) });
    setSaved(true);
  });
  return (
    <Card title="Organization">
      <Async q={q}>
        {() => f && (
          <form className="space-y-3 max-w-md" onSubmit={async (e) => { e.preventDefault(); setSaved(false); await save.run(); }}>
            <label className="block text-sm"><span className="block mb-1 text-gray-700 dark:text-gray-200">Name</span><input className={inputClass} disabled={!can("admin")} value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></label>
            <label className="block text-sm"><span className="block mb-1 text-gray-700 dark:text-gray-200">Industry</span><input className={inputClass} disabled={!can("admin")} value={f.industry} onChange={(e) => setF({ ...f, industry: e.target.value })} /></label>
            <label className="block text-sm"><span className="block mb-1 text-gray-700 dark:text-gray-200">Region</span><input className={inputClass} disabled={!can("admin")} value={f.region} onChange={(e) => setF({ ...f, region: e.target.value })} /></label>
            <label className="block text-sm"><span className="block mb-1 text-gray-700 dark:text-gray-200">Size</span>
              <select className={inputClass} disabled={!can("admin")} value={f.size} onChange={(e) => setF({ ...f, size: e.target.value as OrganizationSettings["size"] })}>
                {["small", "medium", "large", "enterprise"].map((s) => <option key={s} value={s}>{titleCase(s)}</option>)}
              </select>
            </label>
            <label className="block text-sm"><span className="block mb-1 text-gray-700 dark:text-gray-200">Compliance frameworks (comma-separated)</span><input className={inputClass} disabled={!can("admin")} value={frameworks} onChange={(e) => setFrameworks(e.target.value)} placeholder="ISO 27001, SOC 2, RBI" /></label>
            {save.error && <p className="text-sm text-critical" role="alert">{save.error}</p>}
            {can("admin") && <div className="flex items-center gap-3"><Button type="submit" disabled={save.pending}>Save</Button><Saved ok={saved} /></div>}
          </form>
        )}
      </Async>
    </Card>
  );
}

function Integrations() {
  const q = useQuery(() => api.settings.integrations(), []);
  const [notify, setNotify] = useState("");
  const [contain, setContain] = useState("");
  const [saved, setSaved] = useState(false);
  const save = useAction(async () => {
    await api.settings.saveIntegrations({ notification_webhook_url: notify, containment_webhook_url: contain });
    setNotify("");
    setContain("");
    setSaved(true);
    await q.refetch();
  });
  const info = q.data;
  return (
    <Card title="Webhook integrations">
      <p className="text-xs text-gray-600 dark:text-gray-300 mb-3 max-w-xl">
        The notification webhook receives incident and critical-risk events (Slack-compatible JSON). The containment webhook is called when an asset is isolated or restored,
        so your firewall/EDR automation can act. Stored URLs are never shown in full.
      </p>
      <form className="space-y-3 max-w-xl" onSubmit={async (e) => { e.preventDefault(); setSaved(false); await save.run(); }}>
        <label className="block text-sm">
          <span className="block mb-1 text-gray-700 dark:text-gray-200">Notification webhook {info?.notification_webhook_url?.configured && <em className="text-success">(configured: {info.notification_webhook_url.preview})</em>}</span>
          <input type="url" className={inputClass} value={notify} onChange={(e) => setNotify(e.target.value)} placeholder="https://hooks.example.com/…" />
        </label>
        <label className="block text-sm">
          <span className="block mb-1 text-gray-700 dark:text-gray-200">Containment webhook {info?.containment_webhook_url?.configured && <em className="text-success">(configured: {info.containment_webhook_url.preview})</em>}</span>
          <input type="url" className={inputClass} value={contain} onChange={(e) => setContain(e.target.value)} placeholder="https://automation.example.com/…" />
        </label>
        <p className="text-xs text-gray-500 dark:text-gray-300">Leave a field empty and save to remove that webhook.</p>
        {save.error && <p className="text-sm text-critical" role="alert">{save.error}</p>}
        <div className="flex items-center gap-3"><Button type="submit" disabled={save.pending}>Save</Button><Saved ok={saved} /></div>
      </form>
    </Card>
  );
}

function Users() {
  const { user: me } = useAuth();
  const q = useQuery(() => api.users.list(), []);
  const [form, setForm] = useState({ email: "", username: "", full_name: "", password: "", role: "analyst" as Role });
  const create = useAction(async () => {
    await api.users.create({ ...form, full_name: form.full_name || undefined });
    setForm({ email: "", username: "", full_name: "", password: "", role: "analyst" });
    await q.refetch();
  });
  const update = useAction(async (u: User, patch: { role?: Role; is_active?: boolean }) => {
    await api.users.update(u.id, patch);
    await q.refetch();
  });
  return (
    <div className="grid xl:grid-cols-2 gap-3">
      <Card title="Users">
        <Async q={q}>
          {(users) => (
            <ul className="divide-y divide-gray-100 dark:divide-gray-700">
              {users.map((u) => (
                <li key={u.id} className="py-2 flex items-center gap-3 text-sm">
                  <div className="flex-1 min-w-0">
                    <p className="font-medium text-gray-900 dark:text-white truncate">{u.full_name || u.username} {!u.is_active && <span className="text-xs text-warning">(disabled)</span>}</p>
                    <p className="text-xs text-gray-500 dark:text-gray-300 truncate">{u.email} · last login {u.last_login_at ? timeAgo(u.last_login_at) : "never"}</p>
                  </div>
                  <select aria-label={`Role for ${u.email}`} className={`${inputClass} !w-auto`} disabled={u.id === me?.id || update.pending} value={u.role} onChange={(e) => update.run(u, { role: e.target.value as Role })}>
                    {["admin", "analyst", "viewer"].map((r) => <option key={r} value={r}>{titleCase(r)}</option>)}
                  </select>
                  <Button variant="secondary" disabled={u.id === me?.id || update.pending} onClick={() => update.run(u, { is_active: !u.is_active })}>{u.is_active ? "Disable" : "Enable"}</Button>
                </li>
              ))}
            </ul>
          )}
        </Async>
        {update.error && <p className="text-sm text-critical mt-2" role="alert">{update.error}</p>}
      </Card>
      <Card title="Add user">
        <form className="space-y-3 max-w-md" onSubmit={async (e) => { e.preventDefault(); await create.run(); }}>
          <input required type="email" className={inputClass} placeholder="Email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
          <input required className={inputClass} placeholder="Username (letters, digits, . _ -)" pattern="[A-Za-z0-9_.\-]{3,100}" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
          <input className={inputClass} placeholder="Full name" value={form.full_name} onChange={(e) => setForm({ ...form, full_name: e.target.value })} />
          <input required type="password" minLength={10} autoComplete="new-password" className={inputClass} placeholder="Initial password (min. 10 characters)" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
          <select className={inputClass} value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as Role })}>
            {["admin", "analyst", "viewer"].map((r) => <option key={r} value={r}>{titleCase(r)}</option>)}
          </select>
          {create.error && <p className="text-sm text-critical" role="alert">{create.error}</p>}
          <Button type="submit" disabled={create.pending}>Create user</Button>
        </form>
      </Card>
    </div>
  );
}

function System() {
  const q = useQuery(() => api.settings.system(), [], 15000);
  const run = useAction(async (id: string) => {
    await api.settings.runJob(id);
    setTimeout(q.refetch, 1500);
  });
  return (
    <Async q={q}>
      {(s) => (
        <div className="grid xl:grid-cols-2 gap-3">
          <Card title="Platform status">
            <dl className="grid grid-cols-2 gap-3 text-sm text-gray-800 dark:text-gray-100">
              <div><dt className="text-xs text-gray-500 dark:text-gray-300">Environment</dt><dd className="font-medium">{s.environment}</dd></div>
              <div><dt className="text-xs text-gray-500 dark:text-gray-300">Database</dt><dd className="font-medium">{s.database.engine} · {s.database.status}</dd></div>
              <div><dt className="text-xs text-gray-500 dark:text-gray-300">AI agents</dt><dd className="font-medium">{s.ai.configured ? s.ai.provider : "Rules-engine mode (no GEMINI_API_KEY)"}</dd></div>
              <div><dt className="text-xs text-gray-500 dark:text-gray-300">NVD API key</dt><dd className="font-medium">{s.feeds.nvd_api_key ? "Configured" : "Not set (public rate limit)"}</dd></div>
              <div><dt className="text-xs text-gray-500 dark:text-gray-300">SIEM ingest API key</dt><dd className="font-medium">{s.siem.ingest_api_key_set ? "Configured" : "Not set (JWT only)"}</dd></div>
              <div><dt className="text-xs text-gray-500 dark:text-gray-300">Audit ledger</dt><dd className={`font-medium ${s.ledger.valid ? "text-success" : "text-critical"}`}>{s.ledger.valid ? `Intact (${s.ledger.blocks} blocks)` : "INTEGRITY FAILURE"}</dd></div>
              {Object.entries(s.counts).map(([k, v]) => <div key={k}><dt className="text-xs text-gray-500 dark:text-gray-300">{titleCase(k)}</dt><dd className="font-medium">{v.toLocaleString()}</dd></div>)}
            </dl>
          </Card>
          <Card title="Background jobs">
            <ul className="space-y-3">
              {s.jobs.map((j) => (
                <li key={j.id} className="p-3 rounded-md border border-gray-200 dark:border-gray-700">
                  <div className="flex items-center justify-between gap-2">
                    <p className="text-sm font-medium text-gray-900 dark:text-white">{j.name}</p>
                    <Button variant="secondary" disabled={j.running || run.pending} onClick={() => run.run(j.id)}>{j.running ? "Running…" : "Run now"}</Button>
                  </div>
                  <p className="text-xs text-gray-500 dark:text-gray-300 mt-1">
                    {j.scheduled ? `Next: ${fmtDate(j.next_run)}` : "Not scheduled"}
                    {j.last_run && ` · last ${j.last_run.status} ${timeAgo(j.last_run.started_at)}`}
                  </p>
                  {j.last_run?.status === "failed" && <p className="text-xs text-critical mt-1">{JSON.stringify(j.last_run.detail).slice(0, 200)}</p>}
                  {j.id === "feed_sync" && Array.isArray((j.last_run?.detail as { errors?: string[] } | undefined)?.errors) && ((j.last_run!.detail as { errors: string[] }).errors.length > 0) && (
                    <p className="text-xs text-warning mt-1">{(j.last_run!.detail as { errors: string[] }).errors.join(" · ").slice(0, 300)}</p>
                  )}
                </li>
              ))}
            </ul>
            {run.error && <p className="text-sm text-critical mt-2" role="alert">{run.error}</p>}
          </Card>
        </div>
      )}
    </Async>
  );
}

export default function SettingsView() {
  const { can } = useAuth();
  const [tab, setTab] = useState<Tab>("profile");
  const tabs: [Tab, string, boolean][] = [
    ["profile", "Profile", true], ["organization", "Organization", true], ["integrations", "Integrations", can("admin")],
    ["users", "Users", can("admin")], ["system", "System", can("admin")],
  ];
  return (
    <div className="space-y-3">
      <div role="tablist" className="flex gap-1 border-b border-gray-200 dark:border-gray-700">
        {tabs.filter(([, , show]) => show).map(([id, label]) => (
          <button
            key={id}
            role="tab"
            aria-selected={tab === id}
            onClick={() => setTab(id)}
            className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px ${tab === id ? "border-primary text-primary" : "border-transparent text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white"}`}
          >
            {label}
          </button>
        ))}
      </div>
      {tab === "profile" && <Profile />}
      {tab === "organization" && <Organization />}
      {tab === "integrations" && can("admin") && <Integrations />}
      {tab === "users" && can("admin") && <Users />}
      {tab === "system" && can("admin") && <System />}
    </div>
  );
}
