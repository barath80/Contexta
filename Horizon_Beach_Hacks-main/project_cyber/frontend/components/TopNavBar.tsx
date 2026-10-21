"use client";

import { useEffect, useRef, useState } from "react";
import { Search, Bell, User as UserIcon, LogOut } from "lucide-react";
import { api, type SearchResults } from "@/lib/api";
import { useAuth } from "@/contexts/AuthContext";
import { useQuery } from "@/hooks/useQuery";
import type { Navigate } from "@/app/page";

const GROUPS: { key: keyof SearchResults["results"]; label: string; view: string }[] = [
  { key: "cves", label: "CVEs", view: "risks" },
  { key: "assets", label: "Assets", view: "assets" },
  { key: "risks", label: "Risks", view: "risks" },
  { key: "incidents", label: "Incidents", view: "incidents" },
  { key: "events", label: "Events", view: "alerts" },
];

export default function TopNavBar({ onNavigate }: { onNavigate: Navigate }) {
  const { user, logout } = useAuth();
  const [term, setTerm] = useState("");
  const [results, setResults] = useState<SearchResults | null>(null);
  const [searchError, setSearchError] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  const unread = useQuery(() => api.alerts.unread(), [], 30000);

  // Debounced global search
  useEffect(() => {
    const q = term.trim();
    if (q.length < 2) {
      setResults(null);
      setSearchError(null);
      return;
    }
    let cancelled = false;
    const t = setTimeout(async () => {
      try {
        const r = await api.search(q);
        if (!cancelled) {
          setResults(r);
          setSearchError(null);
        }
      } catch (e) {
        if (!cancelled) setSearchError(e instanceof Error ? e.message : "Search failed");
      }
    }, 300);
    return () => {
      cancelled = true;
      clearTimeout(t);
    };
  }, [term]);

  useEffect(() => {
    const close = (e: MouseEvent) => {
      if (box.current && !box.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, []);

  const count = unread.data?.unread ?? 0;
  const display = user?.full_name || user?.username || "";

  return (
    <nav className="fixed top-0 left-0 right-0 h-16 bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 z-50 shadow-sm transition-colors">
      <div className="flex items-center justify-between h-full px-6">
        <div className="flex items-center space-x-3">
          <div className="w-8 h-8 bg-primary rounded flex items-center justify-center">
            <span className="text-white font-bold text-lg">C</span>
          </div>
          <span className="text-xl font-semibold text-gray-900 dark:text-white">CONTEXTA</span>
        </div>

        <div className="flex-1 max-w-2xl mx-8 relative" ref={box}>
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400 w-5 h-5" />
          <input
            type="search"
            value={term}
            onChange={(e) => {
              setTerm(e.target.value);
              setOpen(true);
            }}
            onFocus={() => setOpen(true)}
            placeholder="Search CVE / IP / Asset / Incident…"
            aria-label="Global search"
            className="w-full pl-10 pr-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-primary text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-400"
          />
          {open && term.trim().length >= 2 && (
            <div className="absolute mt-1 w-full max-h-96 overflow-y-auto bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-md shadow-lg">
              {searchError && <p className="p-3 text-sm text-critical">{searchError}</p>}
              {results && results.total === 0 && <p className="p-3 text-sm text-gray-500 dark:text-gray-300">No matches for “{results.query}”.</p>}
              {results &&
                GROUPS.map(
                  (g) =>
                    results.results[g.key].length > 0 && (
                      <div key={g.key}>
                        <p className="px-3 pt-2 text-xs font-semibold uppercase text-gray-500 dark:text-gray-400">{g.label}</p>
                        {results.results[g.key].map((r) => (
                          <button
                            key={r.id}
                            onClick={() => {
                              setOpen(false);
                              onNavigate(g.view, g.key === "cves" || g.key === "events" ? r.title.split(" ")[0] : r.title);
                            }}
                            className="w-full text-left px-3 py-2 hover:bg-gray-100 dark:hover:bg-gray-700"
                          >
                            <span className="text-sm text-gray-900 dark:text-white block truncate">{r.title}</span>
                            <span className="text-xs text-gray-500 dark:text-gray-300 block truncate">
                              {r.subtitle} {r.badge && `· ${r.badge}`}
                            </span>
                          </button>
                        ))}
                      </div>
                    ),
                )}
            </div>
          )}
        </div>

        <div className="flex items-center space-x-4">
          <button
            onClick={() => onNavigate("alerts")}
            aria-label={`Alerts${count ? `, ${count} unread` : ""}`}
            className="relative p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-md transition-colors"
          >
            <Bell className="w-5 h-5 text-gray-600 dark:text-white" />
            {count > 0 && (
              <span className="absolute -top-0.5 -right-0.5 min-w-5 h-5 px-1 bg-critical text-white text-xs rounded-full flex items-center justify-center font-semibold">
                {count > 99 ? "99+" : count}
              </span>
            )}
          </button>

          <div className="flex items-center space-x-2 px-2 py-1">
            <div className="w-8 h-8 bg-primary rounded-full flex items-center justify-center">
              <UserIcon className="w-5 h-5 text-white" />
            </div>
            <div className="leading-tight hidden md:block">
              <p className="text-sm font-medium text-gray-700 dark:text-white">{display}</p>
              <p className="text-xs text-gray-500 dark:text-gray-300 capitalize">{user?.role}</p>
            </div>
          </div>
          <button onClick={logout} aria-label="Sign out" title="Sign out" className="p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-md">
            <LogOut className="w-5 h-5 text-gray-600 dark:text-white" />
          </button>
        </div>
      </div>
    </nav>
  );
}
