'use client'

import { useState } from 'react'
import { ChevronRight } from 'lucide-react'
import { api } from '@/lib/api'
import { useQuery } from '@/hooks/useQuery'
import { Async, Card, LevelBadge, timeAgo } from '@/components/ui'
import RiskDetailModal from '@/components/RiskDetailModal'

export default function TopRisksTable({ onShowMore }: { onShowMore?: () => void }) {
  const q = useQuery(() => api.risks.top(5), [], 60000)
  const [open, setOpen] = useState<string | null>(null)
  return (
    <Card
      title="Top Business Risks"
      action={q.data && <span className="text-xs text-gray-500 dark:text-gray-300">scored {timeAgo(q.data.last_calculated)}</span>}
    >
      <Async q={q} empty={{ when: (d) => d.risks.length === 0, title: 'No open risks', hint: 'Risks appear once assets are in the inventory and threat feeds have synced.' }}>
        {(d) => (
          <>
            <ul className="divide-y divide-gray-100 dark:divide-gray-700">
              {d.risks.map((r, i) => (
                <li key={r.id}>
                  <button onClick={() => setOpen(r.id)} className="w-full text-left py-2 flex items-center gap-3 hover:bg-gray-50 dark:hover:bg-gray-700/50 px-1 rounded">
                    <span className="w-5 text-xs text-gray-400">{i + 1}</span>
                    <span className="flex-1 min-w-0">
                      <span className="block text-sm font-medium text-gray-900 dark:text-white truncate">{r.title}</span>
                      <span className="block text-xs text-gray-500 dark:text-gray-300 truncate">{r.asset?.name ?? 'Unmapped'}{r.cve?.cisa_kev && ' · actively exploited'}</span>
                    </span>
                    <span className="text-sm font-bold text-gray-900 dark:text-white">{r.bwvs_score.toFixed(0)}</span>
                    <LevelBadge level={r.level} />
                  </button>
                </li>
              ))}
            </ul>
            <button onClick={onShowMore} className="w-full mt-2 flex items-center justify-center gap-1 py-2 text-primary hover:bg-blue-50 dark:hover:bg-gray-700 rounded text-sm font-medium">
              View all risks <ChevronRight className="w-4 h-4" />
            </button>
          </>
        )}
      </Async>
      {open && <RiskDetailModal riskId={open} onClose={() => setOpen(null)} onChanged={q.refetch} />}
    </Card>
  )
}
