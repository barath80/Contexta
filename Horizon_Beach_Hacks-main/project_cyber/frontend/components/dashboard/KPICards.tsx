'use client'

import { Shield, AlertTriangle, Server, Clock, Activity } from 'lucide-react'
import { api } from '@/lib/api'
import { useQuery } from '@/hooks/useQuery'
import { Async } from '@/components/ui'

const threatColor: Record<string, string> = {
  CRITICAL: 'text-critical',
  HIGH: 'text-critical',
  ELEVATED: 'text-warning',
  GUARDED: 'text-primary',
  LOW: 'text-success',
}

function Delta({ value }: { value: number | null | undefined }) {
  if (value === null || value === undefined) return <span className="text-xs text-gray-400">no 24h baseline</span>
  if (value === 0) return <span className="text-xs text-gray-500 dark:text-gray-300">no change</span>
  return <span className={`text-xs font-semibold ${value > 0 ? 'text-critical' : 'text-success'}`}>{value > 0 ? '+' : ''}{value} 24h</span>
}

export default function KPICards() {
  const q = useQuery(() => api.dashboard.overview(), [], 60000)
  return (
    <Async q={q}>
      {(o) => {
        const kpis = [
          { label: 'Overall Risk Score', value: o.overall_risk_score.toFixed(0), sub: <Delta value={o.delta_24h?.avg_bwvs} />, icon: Shield, color: 'text-critical', bg: 'bg-red-50' },
          { label: 'Active Incidents', value: String(o.active_incidents), sub: <span className="text-xs text-gray-500 dark:text-gray-300">{o.critical_incidents} critical</span>, icon: AlertTriangle, color: 'text-warning', bg: 'bg-amber-50' },
          { label: 'Critical Assets', value: String(o.critical_assets), sub: <span className="text-xs text-gray-500 dark:text-gray-300">{o.critical_assets_at_risk} at risk</span>, icon: Server, color: 'text-primary', bg: 'bg-blue-50' },
          { label: 'Mean Time to Resolve', value: o.mean_time_to_resolve_hours === null ? '—' : `${o.mean_time_to_resolve_hours}h`, sub: <span className="text-xs text-gray-500 dark:text-gray-300">resolved incidents</span>, icon: Clock, color: 'text-success', bg: 'bg-green-50' },
          { label: 'Threat Level', value: o.threat_level.level, sub: <span className="text-xs text-gray-500 dark:text-gray-300 line-clamp-2" title={o.threat_level.reason}>{o.threat_level.reason}</span>, icon: Activity, color: threatColor[o.threat_level.level] ?? 'text-primary', bg: 'bg-red-50' },
        ]
        return (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-5 gap-3">
            {kpis.map((k) => {
              const Icon = k.icon
              return (
                <div key={k.label} className="bg-white dark:bg-gray-800 rounded-md border border-gray-200 dark:border-gray-700 p-3">
                  <div className="flex items-start justify-between mb-2 gap-2">
                    <div className={`${k.bg} dark:bg-gray-700 p-1.5 rounded-md`}><Icon className={`w-4 h-4 ${k.color}`} /></div>
                    <div className="text-right">{k.sub}</div>
                  </div>
                  <div className={`text-xl font-bold mb-0.5 ${k.label === 'Threat Level' ? k.color : 'text-gray-900 dark:text-white'}`}>{k.value}</div>
                  <div className="text-xs text-gray-600 dark:text-white font-medium">{k.label}</div>
                </div>
              )
            })}
          </div>
        )
      }}
    </Async>
  )
}
