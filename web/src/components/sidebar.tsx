"use client";

import {
  Shield,
  LayoutDashboard,
  Radio,
  Grid3x3,
  Route,
  Lock,
  Moon,
  Sun,
  RefreshCw,
  Search,
} from "lucide-react";

export const NAV_SECTIONS = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { id: "live-scanner", label: "Live Scanner", icon: Radio },
  { id: "heatmap", label: "Mosca Heatmap", icon: Grid3x3 },
  { id: "roadmap", label: "PQC Roadmap", icon: Route },
  { id: "inventory", label: "Crypto Inventory", icon: Lock },
] as const;

interface SidebarProps {
  active: string;
  theme: "light" | "dark";
  refreshing: boolean;
  onNavigate: (id: string) => void;
  onToggleTheme: () => void;
  onRefresh: () => void;
  onNewScan: () => void;
}

export function Sidebar({
  active,
  theme,
  refreshing,
  onNavigate,
  onToggleTheme,
  onRefresh,
  onNewScan,
}: SidebarProps) {
  return (
    <aside className="fixed inset-y-0 left-0 z-40 hidden w-64 flex-col border-r border-border bg-card lg:flex">
      {/* Brand */}
      <div className="flex items-center gap-3 border-b border-border px-5 py-5">
        <div className="flex size-9 items-center justify-center rounded-xl bg-primary text-primary-foreground">
          <Shield className="h-5 w-5" aria-hidden="true" />
        </div>
        <div className="leading-tight">
          <p className="font-mono text-base font-black tracking-widest text-foreground">QRYPTON</p>
          <p className="text-xs text-muted-foreground">Before the math changes.</p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto px-3 py-5" aria-label="Primary">
        <p className="qrypton-kicker px-3 pb-2">Command center</p>
        <ul className="flex flex-col gap-1">
          {NAV_SECTIONS.map(({ id, label, icon: Icon }) => {
            const isActive = active === id;
            return (
              <li key={id}>
                <button
                  type="button"
                  onClick={() => onNavigate(id)}
                  aria-current={isActive ? "true" : undefined}
                  className={`group relative flex w-full items-center gap-3 rounded-lg border px-3 py-2.5 text-sm font-medium transition-all ${
                    isActive
                      ? "border-border bg-[var(--surface-muted)] text-foreground shadow-sm ring-1 ring-primary/20"
                      : "border-transparent text-muted-foreground hover:bg-[var(--surface-subtle)] hover:text-foreground"
                  }`}
                >
                  <span
                    className={`absolute left-0 top-1/2 h-5 -translate-y-1/2 rounded-full bg-primary transition-all ${
                      isActive ? "w-1 opacity-100" : "w-0 opacity-0"
                    }`}
                    aria-hidden="true"
                  />
                  <Icon
                    className={`h-4 w-4 shrink-0 transition-colors ${
                      isActive ? "text-primary" : "text-muted-foreground group-hover:text-foreground"
                    }`}
                    aria-hidden="true"
                  />
                  {label}
                </button>
              </li>
            );
          })}
        </ul>
      </nav>

      {/* Actions */}
      <div className="border-t border-border p-3">
        <button
          type="button"
          onClick={onNewScan}
          className="mb-3 inline-flex w-full items-center justify-center gap-2 rounded-lg bg-primary px-4 py-2.5 text-sm font-semibold text-primary-foreground shadow-sm transition-opacity hover:opacity-90 active:scale-[0.98]"
        >
          <Search className="h-4 w-4" aria-hidden="true" />
          New Scan
        </button>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={onRefresh}
            disabled={refreshing}
            title="Refresh inventory and posture"
            className="inline-flex flex-1 items-center justify-center gap-2 rounded-lg border border-border px-3 py-2 text-xs font-medium text-muted-foreground transition-colors hover:bg-[var(--surface-subtle)] hover:text-foreground disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? "animate-spin text-primary" : ""}`} aria-hidden="true" />
            Refresh
          </button>
          <button
            type="button"
            onClick={onToggleTheme}
            title={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
            aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
            className="inline-flex items-center justify-center rounded-lg border border-border px-3 py-2 text-muted-foreground transition-colors hover:bg-[var(--surface-subtle)] hover:text-foreground"
          >
            {theme === "dark" ? <Sun className="h-3.5 w-3.5" aria-hidden="true" /> : <Moon className="h-3.5 w-3.5" aria-hidden="true" />}
          </button>
        </div>
      </div>
    </aside>
  );
}
