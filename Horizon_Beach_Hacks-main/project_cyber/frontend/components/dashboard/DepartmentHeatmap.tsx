'use client'

import { api } from '@/lib/api'
import { useQuery } from '@/hooks/useQuery'
import { Async, Card } from '@/components/ui'

const barColor = (risk: number) => (risk >= 80 ? 'bg-red-500' : risk >= 60 ? 'bg-orange-500' : risk >= 40 ? 'bg-yellow-400' : 'bg-blue-400')

export default function DepartmentHeatmap() {
  const q = useQuery(() => api.dashboard.departments(), [], 120000)
  return (
    <Card title="Business Unit Risk">
      <Async q={q} empty={{ when: (d) => d.length === 0, title: 'No business units', hint: 'Assign a business unit to assets to see risk by department.' }}>
        {(depts) => (
          <div className="space-y-2.5">
            {depts.map((d) => (
              <div key={d.name} className="flex items-center gap-2" title={`${d.assets} assets · ${d.open_risks} open risks · max BWVS ${d.max_bwvs}`}>
                <div className="w-28 text-xs font-medium text-gray-900 dark:text-white truncate">{d.name}</div>
                <div className="flex-1 bg-gray-200 dark:bg-gray-700 rounded-full h-6 overflow-hidden">
                  <div className={`${barColor(d.risk)} h-full rounded-full flex items-center justify-end pr-2`} style={{ width: `${Math.max(d.risk, 8)}%` }}>
                    <span className="text-xs font-bold text-black">{d.risk}</span>
                  </div>
                </div>
                <div className="w-16 text-xs text-gray-700 dark:text-white text-right">{d.incidents} inc</div>
              </div>
            ))}
          </div>
        )}
      </Async>
    </Card>
  )
}
