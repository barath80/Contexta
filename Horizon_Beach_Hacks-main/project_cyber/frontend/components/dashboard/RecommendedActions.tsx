'use client'

import { Play, Siren, ChevronRight } from 'lucide-react'
import { api } from '@/lib/api'
import { useQuery } from '@/hooks/useQuery'
import { Async, Card } from '@/components/ui'

const priorityStyle: Record<string, string> = {
  critical: 'border-critical hover:bg-red-50 dark:hover:bg-gray-700',
  high: 'border-warning hover:bg-amber-50 dark:hover:bg-gray-700',
  medium: 'border-blue-500 hover:bg-blue-50 dark:hover:bg-gray-700',
  low: 'border-gray-400 hover:bg-gray-50 dark:hover:bg-gray-700',
}

export default function RecommendedActions({ onViewAll }: { onViewAll?: () => void }) {
  const q = useQuery(() => api.dashboard.actions(5), [], 60000)
  return (
    <Card title="Recommended Actions">
      <Async q={q} empty={{ when: (d) => d.length === 0, title: 'Nothing needs action right now' }}>
        {(actions) => (
          <ul className="space-y-1.5">
            {actions.map((a, i) => (
              <li key={i} className={`flex items-start gap-2 p-2 border-l-4 rounded-r ${priorityStyle[a.priority] ?? priorityStyle.low}`}>
                {a.kind === 'incident' ? <Siren className="w-3.5 h-3.5 mt-0.5 shrink-0" /> : <Play className="w-3.5 h-3.5 mt-0.5 shrink-0" />}
                <div className="min-w-0">
                  <p className="text-xs font-medium text-gray-900 dark:text-white">{a.label}</p>
                  {a.reason && <p className="text-xs text-gray-500 dark:text-gray-300">{a.reason}</p>}
                </div>
              </li>
            ))}
          </ul>
        )}
      </Async>
      <button onClick={onViewAll} className="w-full mt-3 flex items-center justify-center gap-1 py-2 text-primary hover:bg-blue-50 dark:hover:bg-gray-700 rounded text-sm font-medium">
        Open playbooks <ChevronRight className="w-4 h-4" />
      </button>
    </Card>
  )
}
