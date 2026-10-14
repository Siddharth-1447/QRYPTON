"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  LayoutDashboard,
  Activity,
  History,
  ClipboardList,
  FileSearch,
  Route,
  Lock,
  BarChart3,
  Plug,
  PanelLeftClose,
  PanelLeftOpen,
} from "lucide-react";
import { GlossaryText } from "@/components/glossary";
import { Logo } from "@/components/logo";
import { NETWORK_SAMPLE_MODE } from "@/lib/network-sample";

export const NAV_SECTIONS = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { id: "results-section", label: "Results", icon: FileSearch },
  { id: "inventory", label: "Crypto Inventory", icon: Lock },
  { id: "risk", label: "Risk & Prioritization", icon: BarChart3 },
  { id: "roadmap", label: "Migration Roadmap", icon: Route },
  { id: "reports", label: "CBOM / Reports", icon: History },
  { id: "integrations", label: "Integrations", icon: Plug },
  ...(NETWORK_SAMPLE_MODE ? [{ id: "live-scanner", label: "Network Inspection", icon: Activity }] : []),
  { id: "your-scans", label: "Your Scans", icon: ClipboardList },
] as const;

export const SIDEBAR_MIN_WIDTH = 240;
export const SIDEBAR_MAX_WIDTH = 420;
export const SIDEBAR_DEFAULT_WIDTH = 304;
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

  return (
    <aside
      aria-label="Primary"
      style={{ width: collapsed ? 72 : width }}
      className={`fixed inset-y-0 left-0 z-40 hidden flex-col border-r border-border bg-sidebar lg:flex ${
        dragging ? "" : "qrypton-motion "
      }`}
    >
      {/* Brand */}
      <div className={`flex items-center gap-2 border-b border-border px-4 py-5 ${compact || collapsed ? "flex-col justify-center" : ""}`}>
        <Logo tone="on-dark" lockup={!compact && !collapsed} tagline={!compact && !collapsed ? "Before the math changes." : undefined} className={compact || collapsed ? "size-11 shrink-0" : "h-11 min-w-0 flex-1"} />
        {(!compact || collapsed) && (
          <button
            type="button"
            onClick={onToggleCollapsed}
            title={collapsed ? "Expand navigation" : "Show navigation icons only"}
            aria-label={collapsed ? "Expand navigation" : "Show navigation icons only"}
            className="rounded-md p-1.5 text-muted-foreground qrypton-motion hover:bg-[var(--surface-subtle)] hover:text-foreground"
          >
            {collapsed ? <PanelLeftOpen className="h-4 w-4" aria-hidden="true" /> : <PanelLeftClose className="h-4 w-4" aria-hidden="true" />}
          </button>
        )}
      </div>

      {/* Navigation — plain list like the reference: no bordered boxes, neutral surface on active */}
      <nav className={`flex-1 overflow-y-auto py-6 ${collapsed ? "px-2" : "px-4"}`} aria-label="Primary">
        <ul className="relative isolate flex flex-col gap-0">
          <li aria-hidden="true" className="pointer-events-none absolute inset-x-0 top-0 -z-10 h-10 rounded-lg bg-muted qrypton-motion   motion-reduce:transition-none" style={{ transform: `translateY(${Math.max(0, NAV_SECTIONS.findIndex((section) => section.id === active)) * 40}px)` }} />
          {NAV_SECTIONS.map(({ id, label, icon: Icon }) => {
            const isActive = active === id;
            return (
              <li key={id}>
                <button
                  type="button"
                  onClick={() => onNavigate(id)}
                  aria-current={isActive ? "location" : undefined}
                  title={label}
                  className={`group flex h-10 w-full items-center gap-3 rounded-lg px-4 py-2 text-[length:var(--type-13)] font-medium qrypton-motion ${
                    compact || collapsed ? "justify-center px-2" : ""
                  } ${
                    isActive
                      ? "text-primary"
                      : "text-muted-foreground hover:bg-card hover:text-foreground"
                  }`}
                >
                  <Icon
                    className={`h-4 w-4 shrink-0 ${
                      isActive ? "text-primary" : "text-muted-foreground group-hover:text-foreground"
                    }`}
                    aria-hidden="true"
                  />
                  {!compact && !collapsed && <span className="truncate"><GlossaryText>{label}</GlossaryText></span>}
                </button>
              </li>
            );
          })}
        </ul>
      </nav>

      {/* Mouse resize handle */}
      {!collapsed && <div
        role="separator"
        aria-orientation="vertical"
        aria-label="Resize navigation"
        title="Drag to resize · double-click to reset"
        tabIndex={0}
        aria-valuemin={SIDEBAR_MIN_WIDTH}
        aria-valuemax={SIDEBAR_MAX_WIDTH}
        aria-valuenow={width}
        onKeyDown={e => {
          if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(e.key)) return;
          e.preventDefault();
          onWidthChange(e.key === "Home" ? SIDEBAR_MIN_WIDTH : e.key === "End" ? SIDEBAR_MAX_WIDTH : Math.max(SIDEBAR_MIN_WIDTH, Math.min(SIDEBAR_MAX_WIDTH, width + (e.key === "ArrowLeft" ? -16 : 16))));
        }}
        onMouseDown={(e) => {
          e.preventDefault();
          dragState.current = { startX: e.clientX, startWidth: width };
          setDragging(true);
        }}
        onDoubleClick={() => onWidthChange(SIDEBAR_DEFAULT_WIDTH)}
        className="group absolute inset-y-0 right-0 z-50 flex w-3 translate-x-1/2 cursor-ew-resize items-stretch justify-center bg-transparent focus-visible:outline-2 focus-visible:outline-primary"
      >
        <span
          className={`my-2 w-1 rounded-full qrypton-motion ${
            dragging ? "bg-primary" : "bg-transparent group-hover:bg-primary/50 group-focus-visible:bg-primary"
          }`}
          aria-hidden="true"
        />
      </div>}
    </aside>
  );
}
