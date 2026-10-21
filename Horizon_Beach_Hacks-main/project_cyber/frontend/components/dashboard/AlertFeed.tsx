'use client'

import { ChevronRight } from 'lucide-react'
import { api } from '@/lib/api'
import { useQuery } from '@/hooks/useQuery'
import { Async, Card, LevelBadge, timeAgo, titleCase } from '@/components/ui'

export default function AlertFeed({ onViewAll }: { onViewAll?: () => void }) {
  const q = useQuery(() => api.alerts.list({ page_size: 5, min_severity: 'medium', status: 'new' }), [], 30000)
  return (
    <Card title="Real-Time Alert Feed">
      <Async q={q} empty={{ when: (d) => d.items.length === 0, title: 'No new alerts', hint: 'Push events from your SIEM to POST /api/v1/logs/ingest.' }}>
        {(d) => (
          <ul className="space-y-2">
            {d.items.map((a) => (
              <li key={a.id} className="border-l-4 border-l-primary bg-gray-50 dark:bg-gray-700 p-2 rounded-r">
                <div className="flex items-center justify-between gap-2">
                  <LevelBadge level={a.severity} />
                  <span className="text-xs text-gray-500 dark:text-gray-300">{timeAgo(a.created_at)}</span>
                </div>
                <p className="text-xs text-gray-800 dark:text-white font-medium mt-1 line-clamp-2">{a.message}</p>
                <p className="text-xs text-gray-500 dark:text-gray-300">{titleCase(a.category)}{a.asset_name && ` · ${a.asset_name}`}</p>
              </li>
            ))}
          </ul>
        )}
      </Async>
      <button onClick={onViewAll} className="w-full mt-3 flex items-center justify-center gap-1 py-2 text-primary hover:bg-blue-50 dark:hover:bg-gray-700 rounded text-sm font-medium">
        View all alerts <ChevronRight className="w-4 h-4" />
      </button>
    </Card>
  )
}
