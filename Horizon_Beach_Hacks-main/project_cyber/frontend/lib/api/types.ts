/** Types mirroring the Contexta backend schemas (/api/v1). */

export type Level = 'critical' | 'high' | 'medium' | 'low';
export type Role = 'admin' | 'analyst' | 'viewer';

export interface User {
  id: string;
  email: string;
  username: string;
  full_name: string | null;
  role: Role;
  is_active: boolean;
  is_verified: boolean;
  last_login_at: string | null;
  preferences: Record<string, unknown>;
  created_at: string;
}

// ------------------------------------------------------------------ risks
export type RiskStatus = 'active' | 'investigating' | 'mitigating' | 'resolved' | 'accepted';

export interface RiskCVE {
  id: string;
  cve_id: string;
  cvss_score: number;
  severity: string | null;
  cisa_kev: boolean;
  has_exploit: boolean;
  epss_score: number | null;
  description: string;
  published_date: string | null;
}

export interface RiskAsset {
  id: string;
  name: string;
  hostname: string | null;
  ip_address: string | null;
  asset_type: string;
  exposure_level: string;
  criticality: string;
  business_unit: string | null;
  is_isolated: boolean;
}

export interface BWVSComponents {
  cvss_score: number;
  exploit_activity: number;
  exposure_level: number;
  asset_criticality: number;
  business_impact: number;
  ai_relevance: number;
  final_bwvs: number;
}

export interface Risk {
  id: string;
  title: string;
  description: string | null;
  category: string;
  source: string;
  bwvs_score: number;
  priority_score: number;
  level: Level;
  status: RiskStatus;
  ai_relevance_score: number;
  ai_analysis: Record<string, unknown>;
  first_seen: string;
  last_seen: string;
  resolved_at: string | null;
  is_top_10: boolean;
  remediation_notes: string | null;
  match_reasons: string[];
  affected_assets_count: number;
  cve: RiskCVE | null;
  asset: RiskAsset | null;
  components: BWVSComponents | null;
  created_at: string;
  updated_at: string;
}

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export interface TopRisks {
  risks: Risk[];
  last_calculated: string;
  calculation_interval_minutes: number;
}

export interface RiskStats {
  total: number;
  open: number;
  by_status: Record<string, number>;
  by_level: Record<Level, number>;
  average_bwvs: number;
  kev_open: number;
}

export interface ScoreHistoryPoint {
  calculated_at: string;
  bwvs: number;
  cvss: number;
  exploit: number;
  exposure: number;
  criticality: number;
  business_impact: number;
  ai_relevance: number;
}

// ----------------------------------------------------------------- assets
export interface Asset {
  id: string;
  name: string;
  hostname: string | null;
  ip_address: string | null;
  asset_type: string;
  os: string | null;
  software: string[];
  exposure_level: string;
  criticality: string;
  network_zone: string;
  business_unit: string | null;
  owner: string | null;
  location: string | null;
  daily_revenue_impact: number;
  is_active: boolean;
  is_isolated: boolean;
  isolated_at: string | null;
  asset_metadata: Record<string, unknown>;
  exposure_score: number;
  criticality_score: number;
  business_impact_score: number;
  open_risks: number;
  max_bwvs: number;
  risk_level: Level | 'none';
  created_at: string;
  updated_at: string;
}

export type AssetInput = Partial<
  Omit<Asset, 'id' | 'is_isolated' | 'isolated_at' | 'exposure_score' | 'criticality_score' | 'business_impact_score' | 'open_risks' | 'max_bwvs' | 'risk_level' | 'created_at' | 'updated_at'>
> & { name: string; asset_type: string };

export interface AssetStats {
  total: number;
  active: number;
  isolated: number;
  internet_facing: number;
  critical: number;
  by_type: Record<string, number>;
}

// ----------------------------------------------------------------- alerts
export type AlertStatus = 'new' | 'acknowledged' | 'dismissed';

export interface Alert {
  id: string;
  source: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  message: string;
  source_ip: string | null;
  destination_ip: string | null;
  destination_port: number | null;
  username: string | null;
  asset_id: string | null;
  asset_name: string | null;
  status: AlertStatus;
  is_simulated: boolean;
  indicators: Record<string, unknown>;
  raw_log: Record<string, unknown>;
  created_at: string;
}

export interface AlertPage extends Page<Alert> {
  unread: number;
}

export interface AlertStats {
  window_hours: number;
  total: number;
  by_severity: Record<string, number>;
  by_category: Record<string, number>;
  top_source_ips: { ip: string; count: number }[];
}

// -------------------------------------------------------------- incidents
export type IncidentStatus = 'open' | 'analyzing' | 'responding' | 'contained' | 'resolved' | 'closed';

export interface Incident {
  id: string;
  ref: string | null;
  title: string;
  description: string | null;
  incident_type: string;
  risk_id: string | null;
  risk_title: string | null;
  risk_bwvs: number | null;
  status: IncidentStatus;
  severity: Level;
  assigned_to: string | null;
  timeline: { timestamp: string; event: string; details?: string | null; actor?: string | null }[];
  affected_assets: string[];
  affected_asset_names: string[];
  iocs: Record<string, unknown>;
  notes: string | null;
  resolution: string | null;
  resolved_at: string | null;
  created_at: string;
  updated_at: string;
}

// -------------------------------------------------------------- playbooks
export interface PlaybookStep {
  order: number;
  name: string;
  description: string;
  action_type: 'manual' | 'automated';
  action?: string | null;
  required: boolean;
  timeout_minutes: number;
}

export interface Playbook {
  id: string;
  slug: string | null;
  name: string;
  description: string | null;
  category: string;
  version: string;
  severity_threshold: string;
  steps: PlaybookStep[];
  is_active: boolean;
  estimated_duration: number;
  manual_steps: number;
  automated_steps: number;
}

export interface PlaybookRecommendation {
  playbook: Playbook;
  score: number;
  reasons: string[];
}

export interface StepResult {
  order: number;
  name: string;
  action_type: string;
  status: string;
  notes?: string | null;
  started_at?: string | null;
  completed_at?: string | null;
  output?: Record<string, unknown> | null;
  error?: string | null;
}

export interface PlaybookExecution {
  id: string;
  playbook_id: string;
  playbook_name: string | null;
  playbook_slug: string | null;
  risk_id: string | null;
  risk_title: string | null;
  incident_id: string | null;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  started_at: string | null;
  completed_at: string | null;
  step_results: StepResult[];
  progress: number;
  error_message: string | null;
  output: Record<string, unknown>;
  created_at: string;
}

// ------------------------------------------------------------------- CVEs
export interface CVE {
  id: string;
  cve_id: string;
  description: string;
  cvss_score: number;
  severity: string | null;
  affected_software: string[];
  published_date: string | null;
  has_exploit: boolean;
  cisa_kev: boolean;
  kev_ransomware_use: boolean;
  epss_score: number | null;
  epss_percentile: number | null;
  cwes: string[];
  references: string[];
  open_risks: number;
}

// -------------------------------------------------------------- dashboard
export interface Overview {
  overall_risk_score: number;
  security_score: number;
  open_risks: number;
  risks_by_level: Record<Level, number>;
  active_incidents: number;
  critical_incidents: number;
  critical_assets: number;
  critical_assets_at_risk: number;
  mean_time_to_resolve_hours: number | null;
  threat_level: { level: string; reason: string };
  active_vulnerabilities: number;
  critical_threats: number;
  kev_open: number;
  delta_24h: { open_risks: number; critical: number; avg_bwvs: number } | null;
  has_data: boolean;
  assets_total: number;
  generated_at: string;
}

export interface TrendPoint {
  bucket: string;
  label: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  open_total: number;
  avg_bwvs: number;
  exposure_lakhs: number;
}

export interface Trend {
  granularity: 'hour' | 'day' | 'none';
  points: TrendPoint[];
  note: string | null;
}

export interface Department {
  name: string;
  assets: number;
  open_risks: number;
  incidents: number;
  max_bwvs: number;
  avg_bwvs: number;
  risk: number;
  level: Level | 'none';
}

export interface VulnerabilityBucket {
  category: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

export interface RecommendedAction {
  kind: 'incident' | 'risk';
  priority: Level;
  label: string;
  incident_id?: string;
  risk_id?: string | null;
  playbook_slug?: string | null;
  reason?: string;
}

export interface ExposedAsset {
  asset_id: string;
  asset_name: string;
  business_unit: string | null;
  expected_loss_lakhs: number;
  probability: number;
  open_risks: number;
}

export interface Executive {
  business_risk_score: number;
  financial_exposure_lakhs: number;
  exposure_by_business_unit: { name: string; lakhs: number }[];
  top_exposed_assets: ExposedAsset[];
  exposure_by_category: { name: string; lakhs: number }[];
  risk_trend: { label: string; delta_7d: number };
  control_health: {
    kev_open: number;
    internet_facing_assets_with_serious_risk: number;
    critical_sla_days: number;
    critical_sla_breaches: number;
    risks_opened_30d: number;
    risks_resolved_30d: number;
    mean_days_to_resolve: number | null;
  };
  monthly_trend: { month: string; risk_score_10: number; exposure_lakhs: number }[];
  assumptions: string[];
  currency: string;
  generated_at: string;
}

export interface Analytics {
  kpis: {
    incidents_total: number;
    incidents_resolved_pct: number | null;
    mean_time_to_resolve_hours: number | null;
    open_risks: number;
    critical_risks: number;
    risks_resolved: number;
    events_processed: number;
    average_bwvs: number;
  };
  monthly_incidents: { month: string; incidents: number; resolved: number; pending: number }[];
  vulnerability_distribution: VulnerabilityBucket[];
  threat_activity: ({ week: string } & Record<string, number | string>)[];
  top_risks: { title: string; bwvs: number; priority: number; level: Level; asset: string | null; cve: string | null }[];
  generated_at: string;
}

export interface ReportSummary {
  id: string;
  kind: string;
  title: string;
  generated_by: string;
  created_at: string;
  content?: string;
}

export interface SearchResults {
  query: string;
  total: number;
  results: Record<'cves' | 'assets' | 'risks' | 'incidents' | 'events', { id: string; title: string; subtitle: string; badge: string }[]>;
}

// ------------------------------------------------------------ digital twin
export interface TwinNode {
  id: string;
  name: string;
  asset_type: string;
  zone: string;
  criticality: string;
  exposure: string;
  is_isolated: boolean;
  open_risks: number;
  max_bwvs: number;
  risk_level: Level | 'none';
}

export interface TwinTopology {
  nodes: TwinNode[];
  edges: { source: string; target: string; [k: string]: unknown }[];
  stats: Record<string, unknown>;
  entry_points: unknown[];
}

export interface AttackType {
  id: string;
  label: string;
  method: string;
  time_to_impact: string;
  spreads: boolean;
}

export interface SimulationResult {
  simulation_id: string;
  attack_type: string;
  attack_label: string;
  entry_point: string;
  entry_point_name: string;
  target: string | null;
  paths_found: { path?: string[]; path_names?: string[]; [k: string]: unknown }[];
  blast_radius: { id: string; name: string }[];
  compromised_assets: Record<string, unknown>[];
  critical_assets_compromised: Record<string, unknown>[];
  timeline: Record<string, unknown>[];
  risk_assessment: string;
  impact: {
    assets_compromised: number;
    assets_total: number;
    daily_revenue_at_risk_lakhs: number;
    estimated_downtime_days: number;
    estimated_loss_lakhs: number;
    time_to_impact: string;
    primary_method: string;
    blast_risk_score: number;
  };
  recommendations?: string[];
  [k: string]: unknown;
}

// ------------------------------------------------------------------ agents
export interface AgentInfo {
  type: string;
  name: string;
  role: string;
  questions: string[];
}

export interface AgentStatus {
  mode: 'ai' | 'rules';
  provider: string | null;
  ai_configured: boolean;
  note: string | null;
  agents: AgentInfo[];
  pipeline: string[][];
}

export interface AgentMessage {
  agent: string;
  name: string;
  message: string;
  severity: Level;
  confidence: number;
  key_points: string[];
  recommendations: string[];
  addresses: string[];
  data: Record<string, unknown>;
  timestamp?: string;
  source?: string;
  degraded?: string;
}

export interface Consensus {
  consensus_severity: Level;
  threat_level: string;
  confidence_score: number;
  agent_agreement: { score: number; level: string; agents_reporting: number };
  dissent: { agent: string; severity: string; reason: string }[];
  key_findings: { source: string; finding: string; confidence: number }[];
  prioritized_recommendations: { priority: number; recommendation: string; source: string }[];
  immediate_actions: string[];
  recommended_playbook: string | null;
  escalation_required: boolean;
  executive_summary: string;
}

export interface Discussion {
  id: string;
  risk_id: string | null;
  incident_id: string | null;
  title: string;
  status: string;
  generated_by: string;
  messages: AgentMessage[];
  consensus: Partial<Consensus>;
  risk_feedback: Record<string, unknown>;
  duration_ms: number | null;
  error: string | null;
  created_at: string;
}

export type DiscussionEvent =
  | { type: 'started'; discussion_id: string; title: string; generated_by: string; mode: string; agents: string[] }
  | { type: 'typing'; agents: string[] }
  | { type: 'message'; message: AgentMessage }
  | { type: 'consensus'; consensus: Consensus }
  | { type: 'risk_feedback'; feedback: Record<string, unknown> }
  | { type: 'done'; discussion: Discussion }
  | { type: 'error'; code: string; message: string };

// ------------------------------------------------------------------ ledger
export interface LedgerInfo {
  total_blocks: number;
  events_by_type: Record<string, number>;
  head_block: number;
  head_hash: string;
  genesis_timestamp: string;
  latest_timestamp: string;
  signing_key_fingerprint: string;
}

export interface LedgerBlock {
  block_number: number;
  timestamp: string;
  event_type: string;
  actor: string | null;
  resource_type: string | null;
  resource_id: string | null;
  data: Record<string, unknown>;
  previous_hash: string;
  data_hash: string;
  block_hash: string;
  signed: boolean;
}

export interface LedgerVerification {
  valid: boolean;
  blocks_verified: number;
  issues: unknown[];
  [k: string]: unknown;
}

// ----------------------------------------------------------------- settings
export interface OrganizationSettings {
  name: string;
  industry: string;
  region: string;
  size: 'small' | 'medium' | 'large' | 'enterprise';
  compliance_frameworks: string[];
}

export interface JobStatus {
  id: string;
  name: string;
  scheduled: boolean;
  enabled: boolean;
  next_run: string | null;
  running: boolean;
  last_run: { started_at: string; finished_at: string | null; status: string; detail: Record<string, unknown> } | null;
}

export interface SystemStatus {
  environment: string;
  database: { status: string; engine: string };
  ai: { configured: boolean; provider: string | null; mode: string };
  feeds: { nvd_api_key: boolean; cisa_kev_url: string };
  siem: { ingest_api_key_set: boolean };
  registration_enabled: boolean;
  counts: { assets: number; cves: number; risks: number; users: number };
  ledger: { valid: boolean; blocks: number; issues: unknown[] };
  jobs: JobStatus[];
  generated_at: string;
}
