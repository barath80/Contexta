'use client'

import type { Navigate } from '@/app/page'
import KPICards from './dashboard/KPICards'
import TopRisksTable from './dashboard/TopRisksTable'
import RiskTrendChart from './dashboard/RiskTrendChart'
import VulnerabilityChart from './dashboard/VulnerabilityChart'
import DepartmentHeatmap from './dashboard/DepartmentHeatmap'
import AlertFeed from './dashboard/AlertFeed'
import ThreatInsights from './dashboard/ThreatInsights'
import RecommendedActions from './dashboard/RecommendedActions'
import RealTimeRisk from './dashboard/RealTimeRisk'

export default function Dashboard({ onNavigate }: { onNavigate: Navigate }) {
  return (
    <div className="space-y-3">
      <KPICards />
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-3">
        <div className="space-y-3">
          <TopRisksTable onShowMore={() => onNavigate('risks')} />
          <AlertFeed onViewAll={() => onNavigate('alerts')} />
        </div>
        <div className="space-y-3">
          <RealTimeRisk />
          <RiskTrendChart />
          <VulnerabilityChart />
          <DepartmentHeatmap />
        </div>
        <div className="space-y-3">
          <RecommendedActions onViewAll={() => onNavigate('actions')} />
          <ThreatInsights />
        </div>
      </div>
    </div>
  )
}
