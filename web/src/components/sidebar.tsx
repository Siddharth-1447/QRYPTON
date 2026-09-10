"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  LayoutDashboard,
  History,
  ScanSearch,
  FileSearch,
  Route,
  Lock,
  BarChart3,
  Plug,
  PanelLeftClose,
  PanelLeftOpen,
} from "lucide-react";
import { CryptoLockVisual } from "@/components/crypto-lock-visual";

export const NAV_SECTIONS = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { id: "scans", label: "Past Scans", icon: ScanSearch },
  { id: "results-section", label: "Results", icon: FileSearch },
  { id: "inventory", label: "Crypto Inventory", icon: Lock },
  { id: "risk", label: "Risk & Prioritization", icon: BarChart3 },
  { id: "roadmap", label: "Migration Roadmap", icon: Route },
  { id: "reports", label: "Reports / CBOM", icon: History },
  { id: "integrations", label: "Integrations", icon: Plug },
] as const;

export const SIDEBAR_MIN_WIDTH = 176;
export const SIDEBAR_MAX_WIDTH = 360;
export const SIDEBAR_DEFAULT_WIDTH = 256;
export const SIDEBAR_COLLAPSE_THRESHOLD = 140;

interface SidebarProps {
  active: string;
  onNavigate: (id: string) => void;
  width: number;
  onWidthChange: (width: number) => void;
  collapsed: boolean;
  onToggleCollapsed: () => void;
}

export function Sidebar({
  active,
  onNavigate,
  width,
  onWidthChange,
  collapsed,
  onToggleCollapsed,
}: SidebarProps) {
  const [dragging, setDragging] = useState(false);
  const dragState = useRef<{ startX: number; startWidth: number } | null>(null);
  const compact = width < 200;

  const onDragMove = useCallback(
    (clientX: number) => {
      const origin = dragState.current;
      if (!origin) return;
      const next = Math.round(origin.startWidth + (clientX - origin.startX));
      // Dragging past the threshold fully minimizes the navbar.
      if (next < SIDEBAR_COLLAPSE_THRESHOLD) {
        onToggleCollapsed();
        dragState.current = null;
        setDragging(false);
        return;
      }
      onWidthChange(Math.min(SIDEBAR_MAX_WIDTH, Math.max(SIDEBAR_MIN_WIDTH, next)));
    },
    [onToggleCollapsed, onWidthChange]
  );

  useEffect(() => {
    if (!dragging) return;
    const handleMove = (e: MouseEvent) => onDragMove(e.clientX);
    const handleUp = () => {
      dragState.current = null;
      setDragging(false);
    };
    window.addEventListener("mousemove", handleMove);
    window.addEventListener("mouseup", handleUp);
    document.body.style.cursor = "ew-resize";
    document.body.style.userSelect = "none";
    return () => {
      window.removeEventListener("mousemove", handleMove);
      window.removeEventListener("mouseup", handleUp);
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    };
  }, [dragging, onDragMove]);

  // Fully minimized: hide the rail and expose a floating reopen button.
  if (collapsed) {
    return (
      <button
        type="button"
        onClick={onToggleCollapsed}
        title="Show navigation"
        aria-label="Show navigation"
        className="fixed left-4 top-4 z-40 hidden items-center justify-center rounded-lg bg-card p-2.5 text-muted-foreground shadow-md transition-colors hover:bg-[var(--surface-subtle)] hover:text-foreground lg:inline-flex"
      >
        <PanelLeftOpen className="h-4 w-4" aria-hidden="true" />
      </button>
    );
  }

  return (
    <aside
      aria-label="Primary"
      style={{ width }}
      className={`fixed inset-y-0 left-0 z-40 hidden flex-col border-r border-border bg-card lg:flex ${
        dragging ? "" : "transition-[width] duration-200"
      }`}
    >
      {/* Brand */}
      <div className={`flex items-center gap-3 border-b border-border px-5 py-5 ${compact ? "justify-center px-3" : ""}`}>
        <CryptoLockVisual navbar />
        {!compact && (
          <div className="min-w-0 flex-1 leading-tight">
            <p className="truncate font-mono text-base font-black tracking-widest text-foreground">QRYPTON</p>
            <p className="truncate text-xs text-muted-foreground">Before the math changes.</p>
          </div>
        )}
        {!compact && (
          <button
            type="button"
            onClick={onToggleCollapsed}
            title="Minimize navigation"
            aria-label="Minimize navigation"
            className="rounded-md p-1.5 text-muted-foreground transition-colors hover:bg-[var(--surface-subtle)] hover:text-foreground"
          >
            <PanelLeftClose className="h-4 w-4" aria-hidden="true" />
          </button>
        )}
      </div>

      {/* Navigation — plain list like the reference: no bordered boxes, green tint on active */}
      <nav className="flex-1 overflow-y-auto px-3 py-5" aria-label="Primary">
        {!compact && <p className="qrypton-kicker px-3 pb-2">Command center</p>}
        <ul className="flex flex-col gap-0.5">
          {NAV_SECTIONS.map(({ id, label, icon: Icon }) => {
            const isActive = active === id;
            return (
              <li key={id}>
                <button
                  type="button"
                  onClick={() => onNavigate(id)}
                  aria-current={isActive ? "page" : undefined}
                  title={compact ? label : undefined}
                  className={`group flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
                    compact ? "justify-center" : ""
                  } ${
                    isActive
                      ? "bg-[rgba(200,255,61,0.12)] text-primary"
                      : "text-muted-foreground hover:bg-white/5 hover:text-foreground"
                  }`}
                >
                  <Icon
                    className={`h-4 w-4 shrink-0 ${
                      isActive ? "text-primary" : "text-muted-foreground group-hover:text-foreground"
                    }`}
                    aria-hidden="true"
                  />
                  {!compact && <span className="truncate">{label}</span>}
                </button>
              </li>
            );
          })}
        </ul>
      </nav>

      {/* Mouse resize handle */}
      <div
        role="separator"
        aria-orientation="vertical"
        aria-label="Resize navigation"
        title="Drag to resize · drag far left to minimize"
        onMouseDown={(e) => {
          e.preventDefault();
          dragState.current = { startX: e.clientX, startWidth: width };
          setDragging(true);
        }}
        onDoubleClick={onToggleCollapsed}
        className="absolute inset-y-0 right-0 flex w-4 translate-x-1/2 cursor-ew-resize items-stretch justify-center bg-transparent"
      >
        <span
          className={`my-2 w-1 rounded-full transition-colors ${
            dragging ? "bg-primary" : "bg-transparent hover:bg-primary/50"
          }`}
          aria-hidden="true"
        />
      </div>
    </aside>
  );
}
