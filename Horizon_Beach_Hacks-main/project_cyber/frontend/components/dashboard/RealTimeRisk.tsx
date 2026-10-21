'use client'

import { Activity } from 'lucide-react'
import { api } from '@/lib/api'
import { useQuery } from '@/hooks/useQuery'
import { Async, Card } from '@/components/ui'

export default function RealTimeRisk() {
  const q = useQuery(() => api.dashboard.overview(), [], 30000)
  return (
    <Card title={<span className="flex items-center gap-2"><Activity className="w-4 h-4 text-primary" /> Real-Time Risk</span>}>
      <Async q={q}>
        {(o) => {
          const metrics = [
            { label: 'Critical Threats', value: o.critical_threats, color: 'text-critical', delta: o.delta_24h?.critical },
            { label: 'Open Vulnerabilities', value: o.active_vulnerabilities, color: 'text-warning', delta: o.delta_24h?.open_risks },
            { label: 'Actively Exploited (KEV)', value: o.kev_open, color: 'text-critical', delta: undefined },
            { label: 'Security Score', value: o.security_score, color: 'text-success', delta: undefined },
          ]
          return (
            <div className="grid grid-cols-2 gap-3">
              {metrics.map((m) => (
                <div key={m.label}>
                  <p className="text-xs text-gray-600 dark:text-white font-medium">{m.label}</p>
                  <p className={`text-2xl font-bold ${m.color}`}>{m.value}</p>
                  {m.delta !== undefined && m.delta !== null && m.delta !== 0 && (
                    <p className={`text-xs font-semibold ${m.delta > 0 ? 'text-critical' : 'text-success'}`}>{m.delta > 0 ? '+' : ''}{m.delta} vs 24h</p>
                  )}
                </div>
              ))}
            </div>
          )
        }}
      </Async>
    </Card>
  )
}
