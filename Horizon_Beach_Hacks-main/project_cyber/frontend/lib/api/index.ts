import { apiClient as c } from './client';
import type * as T from './types';

export * from './types';
export { apiClient, ApiError } from './client';
export { API_CONFIG } from './config';

type Q = Record<string, string | number | boolean | null | undefined>;

export const api = {
  auth: {
    me: () => c.get<T.User>('/auth/me'),
    updateMe: (data: { full_name?: string; preferences?: Record<string, unknown> }) => c.put<T.User>('/auth/me', data),
    changePassword: (current_password: string, new_password: string) =>
      c.post<{ message: string }>('/auth/change-password', { current_password, new_password }),
  },
  users: {
    list: () => c.get<T.User[]>('/users'),
    create: (d: { email: string; username: string; full_name?: string; password: string; role: T.Role }) =>
      c.post<T.User>('/users', d),
    update: (id: string, d: { full_name?: string; role?: T.Role; is_active?: boolean; password?: string }) =>
      c.patch<T.User>(`/users/${id}`, d),
  },
  dashboard: {
    overview: () => c.get<T.Overview>('/dashboard/overview'),
    trend: (days = 30) => c.get<T.Trend>('/dashboard/trend', { days }),
    departments: () => c.get<T.Department[]>('/dashboard/departments'),
    vulnerabilities: () => c.get<T.VulnerabilityBucket[]>('/dashboard/vulnerabilities'),
    actions: (limit = 6) => c.get<T.RecommendedAction[]>('/dashboard/actions', { limit }),
    executive: () => c.get<T.Executive>('/dashboard/executive'),
  },
  reports: {
    analytics: (months = 6, weeks = 6) => c.get<T.Analytics>('/reports/analytics', { months, weeks }),
    list: () => c.get<T.ReportSummary[]>('/reports'),
    get: (id: string) => c.get<T.ReportSummary>(`/reports/${id}`),
    generateBoard: () => c.post<T.ReportSummary>('/reports/board'),
  },
  search: (q: string) => c.get<T.SearchResults>('/search', { q }),
  risks: {
    top: (limit = 10) => c.get<T.TopRisks>('/risks/top10', { limit }),
    list: (q: Q = {}) => c.get<T.Page<T.Risk>>('/risks', q),
    stats: () => c.get<T.RiskStats>('/risks/stats'),
    get: (id: string) => c.get<T.Risk>(`/risks/${id}`),
    setStatus: (id: string, status: T.RiskStatus, notes?: string) => c.put<T.Risk>(`/risks/${id}/status`, { status, notes }),
    recalculate: (id: string) => c.post<T.Risk>(`/risks/${id}/recalculate`),
    history: (id: string) => c.get<T.ScoreHistoryPoint[]>(`/risks/${id}/history`),
    playbooks: (id: string) => c.get<T.PlaybookRecommendation[]>(`/risks/${id}/playbooks`),
    investigate: (id: string) => c.post<T.Incident>(`/risks/${id}/investigate`),
  },
  incidents: {
    list: (q: Q = {}) => c.get<T.Page<T.Incident>>('/incidents', q),
    stats: () => c.get<Record<string, unknown>>('/incidents/stats'),
    get: (id: string) => c.get<T.Incident>(`/incidents/${id}`),
    update: (id: string, d: Partial<{ status: T.IncidentStatus; severity: T.Level; assigned_to: string; notes: string }>) =>
      c.patch<T.Incident>(`/incidents/${id}`, d),
    addNote: (id: string, note: string) => c.post<T.Incident>(`/incidents/${id}/notes`, { note }),
    close: (id: string, resolution: string, resolve_risk = true) =>
      c.post<T.Incident>(`/incidents/${id}/close`, { resolution, resolve_risk }),
  },
  assets: {
    list: (q: Q = {}) => c.get<T.Page<T.Asset>>('/assets', q),
    stats: () => c.get<T.AssetStats>('/assets/stats'),
    create: (d: T.AssetInput) => c.post<T.Asset>('/assets', d),
    update: (id: string, d: Partial<T.AssetInput>) => c.patch<T.Asset>(`/assets/${id}`, d),
    remove: (id: string) => c.delete<void>(`/assets/${id}`),
    import: (assets: T.AssetInput[]) =>
      c.post<{ created: number; skipped: { name: string; reason: string }[]; risks_created: number }>('/assets/import', { assets }),
    risks: (id: string) => c.get<T.Risk[]>(`/assets/${id}/risks`),
    events: (id: string) => c.get<T.Alert[]>(`/assets/${id}/events`),
    isolate: (id: string) => c.post<T.Asset>(`/assets/${id}/isolate`),
    restore: (id: string) => c.post<T.Asset>(`/assets/${id}/restore`),
  },
  cves: {
    list: (q: Q = {}) => c.get<T.Page<T.CVE>>('/cves', q),
    trending: () => c.get<T.CVE[]>('/cves/trending'),
    stats: () => c.get<Record<string, unknown>>('/cves/stats'),
    get: (id: string) => c.get<T.CVE>(`/cves/${id}`),
  },
  alerts: {
    list: (q: Q = {}) => c.get<T.AlertPage>('/alerts', q),
    stats: (hours = 24) => c.get<T.AlertStats>('/alerts/stats', { hours }),
    unread: () => c.get<{ unread: number }>('/alerts/unread'),
    markSeen: () => c.post<{ alerts_seen_at: string }>('/alerts/mark-seen'),
    acknowledge: (id: string) => c.post<T.Alert>(`/alerts/${id}/acknowledge`),
    dismiss: (id: string) => c.post<T.Alert>(`/alerts/${id}/dismiss`),
  },
  playbooks: {
    list: () => c.get<T.Playbook[]>('/playbooks'),
    executions: (q: Q = {}) => c.get<T.Page<T.PlaybookExecution>>('/playbooks/executions', q),
    start: (d: { slug?: string; playbook_id?: string; risk_id?: string; incident_id?: string; resolve_risk?: boolean }) =>
      c.post<T.PlaybookExecution>('/playbooks/executions', d),
    execution: (id: string) => c.get<T.PlaybookExecution>(`/playbooks/executions/${id}`),
    completeStep: (id: string, order: number, notes?: string) =>
      c.post<T.PlaybookExecution>(`/playbooks/executions/${id}/steps/${order}/complete`, { notes }),
    skipStep: (id: string, order: number, notes?: string) =>
      c.post<T.PlaybookExecution>(`/playbooks/executions/${id}/steps/${order}/skip`, { notes }),
    cancel: (id: string) => c.post<T.PlaybookExecution>(`/playbooks/executions/${id}/cancel`),
  },
  agents: {
    status: () => c.get<T.AgentStatus>('/agents/status'),
    discussions: (q: Q = {}) => c.get<T.Discussion[]>('/agents/discussions', q),
    stream: (
      body: { risk_id?: string; incident_id?: string; agents?: string[] },
      onEvent: (e: T.DiscussionEvent) => void,
      signal?: AbortSignal,
    ) => c.stream<T.DiscussionEvent>('/agents/discussions/stream', body, onEvent, signal),
  },
  twin: {
    attackTypes: () => c.get<T.AttackType[]>('/twin/attack-types'),
    topology: () => c.get<T.TwinTopology>('/twin/topology'),
    simulate: (d: { attack_type: string; entry_point?: string; target?: string }) =>
      c.post<T.SimulationResult>('/twin/simulate', d),
  },
  ledger: {
    info: () => c.get<T.LedgerInfo>('/ledger'),
    blocks: (q: Q = {}) => c.get<{ total: number; skip: number; limit: number; blocks: T.LedgerBlock[] }>('/ledger/blocks', q),
    verify: () => c.get<T.LedgerVerification>('/ledger/verify'),
  },
  settings: {
    organization: () => c.get<T.OrganizationSettings>('/settings/organization'),
    saveOrganization: (d: T.OrganizationSettings) => c.put<T.OrganizationSettings>('/settings/organization', d),
    integrations: () =>
      c.get<Record<string, { configured: boolean; preview: string }>>('/settings/integrations'),
    saveIntegrations: (d: { notification_webhook_url: string; containment_webhook_url: string }) =>
      c.put<Record<string, { configured: boolean; preview: string }>>('/settings/integrations', d),
    system: () => c.get<T.SystemStatus>('/settings/system'),
    runJob: (id: string) => c.post<{ job: string; status: string }>(`/settings/jobs/${id}/run`),
  },
};
