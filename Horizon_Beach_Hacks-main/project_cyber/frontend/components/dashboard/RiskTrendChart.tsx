'use client'

import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts'
import { api } from '@/lib/api'
import { useQuery } from '@/hooks/useQuery'
import { Async, Card, LEVEL_COLORS } from '@/components/ui'

export default function RiskTrendChart() {
  const q = useQuery(() => api.dashboard.trend(30), [], 120000)
  return (
    <Card title="Open Risks by Severity (30 days)">
      <Async q={q} empty={{ when: (d) => d.points.length < 2, title: 'Trend history is building', hint: 'A snapshot is recorded each time risks are re-scored; the chart fills in as data accumulates.' }}>
        {(d) => (
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={d.points}>
              <CartesianGrid strokeDasharray="3 3" stroke="#E5E7EB" />
              <XAxis dataKey="label" tick={{ fontSize: 10 }} stroke="#6B7280" />
              <YAxis tick={{ fontSize: 10 }} stroke="#6B7280" allowDecimals={false} />
              <Tooltip contentStyle={{ fontSize: '11px', borderRadius: 4 }} />
              <Legend wrapperStyle={{ fontSize: '10px' }} />
              {(['critical', 'high', 'medium', 'low'] as const).map((k) => (
                <Line key={k} type="monotone" dataKey={k} stroke={LEVEL_COLORS[k]} strokeWidth={1.5} dot={{ r: 2 }} />
              ))}
            </LineChart>
          </ResponsiveContainer>
        )}
      </Async>
    </Card>
  )
}
