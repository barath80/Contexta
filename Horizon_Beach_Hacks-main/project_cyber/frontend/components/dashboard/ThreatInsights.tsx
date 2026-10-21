'use client'

import { api } from '@/lib/api'
import { useQuery } from '@/hooks/useQuery'
import { Async, Card, LevelBadge, timeAgo } from '@/components/ui'

export default function ThreatInsights() {
  const q = useQuery(() => api.cves.trending(), [], 300000)
  return (
    <Card title="Trending Threat Intelligence">
      <Async q={q} empty={{ when: (d) => d.length === 0, title: 'No threat intelligence yet', hint: 'The CISA KEV / NVD feeds sync on start-up and every few hours.' }}>
        {(cves) => (
          <ul className="space-y-2.5">
            {cves.slice(0, 6).map((c) => (
              <li key={c.id} className="p-2 rounded border border-gray-200 dark:border-gray-700">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm font-semibold text-gray-900 dark:text-white">{c.cve_id}</span>
                  <span className="flex items-center gap-1.5">
                    {c.cisa_kev && <LevelBadge level="critical">KEV</LevelBadge>}
                    <span className="text-xs font-bold text-gray-700 dark:text-white">CVSS {c.cvss_score.toFixed(1)}</span>
                  </span>
                </div>
                <p className="text-xs text-gray-600 dark:text-gray-300 mt-1 line-clamp-2">{c.description}</p>
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                  {c.epss_score !== null && `EPSS ${(c.epss_score * 100).toFixed(1)}% · `}
                  {c.open_risks > 0 ? `${c.open_risks} open risk(s) in your environment` : 'No match in your environment'} · {timeAgo(c.published_date)}
                </p>
              </li>
            ))}
          </ul>
        )}
      </Async>
    </Card>
  )
}
