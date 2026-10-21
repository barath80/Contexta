"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import TopNavBar from "@/components/TopNavBar";
import Sidebar from "@/components/Sidebar";
import Dashboard from "@/components/Dashboard";
import AttackSimulator from "@/components/AttackSimulator";
import ExecutiveView from "@/components/ExecutiveView";
import RisksView from "@/components/RisksView";
import AlertsView from "@/components/AlertsView";
import ActionsView from "@/components/ActionsView";
import IncidentsView from "@/components/IncidentsView";
import AssetsView from "@/components/AssetsView";
import ReportsView from "@/components/ReportsView";
import LedgerView from "@/components/LedgerView";
import SettingsView from "@/components/SettingsView";
import { Spinner } from "@/components/ui";
import { useAuth } from "@/contexts/AuthContext";

export interface Navigate {
  (view: string, query?: string): void;
}

export default function Home() {
  const router = useRouter();
  const { user, isLoading } = useAuth();
  const [activeView, setActiveView] = useState("overview");
  const [query, setQuery] = useState("");

  useEffect(() => {
    if (!isLoading && !user) router.replace("/login");
  }, [isLoading, user, router]);

  if (isLoading || !user) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#F8FAFC] dark:bg-gray-900">
        <Spinner label="Loading Contexta…" />
      </div>
    );
  }

  const go: Navigate = (view, q = "") => {
    setQuery(q);
    setActiveView(view);
  };

  return (
    <div className="min-h-screen bg-[#F8FAFC] dark:bg-gray-900 transition-colors">
      <TopNavBar onNavigate={go} />
      <div className="flex">
        <Sidebar activeView={activeView} setActiveView={(v) => go(v)} />
        <main className="flex-1 ml-64 mt-16 p-4 min-w-0">
          {activeView === "overview" && <Dashboard onNavigate={go} />}
          {activeView === "risks" && <RisksView key={query} initialQuery={query} />}
          {activeView === "alerts" && <AlertsView key={query} initialQuery={query} />}
          {activeView === "incidents" && <IncidentsView key={query} initialQuery={query} />}
          {activeView === "actions" && <ActionsView />}
          {activeView === "assets" && <AssetsView key={query} initialQuery={query} />}
          {activeView === "simulator" && <AttackSimulator />}
          {activeView === "executive" && <ExecutiveView />}
          {activeView === "reports" && <ReportsView />}
          {activeView === "ledger" && <LedgerView />}
          {activeView === "settings" && <SettingsView />}
        </main>
      </div>
    </div>
  );
}
