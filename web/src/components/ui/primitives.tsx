import type { ButtonHTMLAttributes, HTMLAttributes, InputHTMLAttributes, ReactNode } from "react";
import { cn } from "@/lib/utils";
import { CircleAlert, TriangleAlert, Diamond, Shield, ShieldCheck, CircleHelp, Info, CircleDashed } from "lucide-react";

export function Button({ className, variant = "primary", ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "ghost" | "danger" }) {
  return <button className={cn("inline-flex min-h-10 items-center justify-center gap-2 rounded-md px-4 text-sm font-semibold qrypton-motion disabled:pointer-events-none disabled:opacity-50", { "bg-primary text-primary-foreground hover:opacity-90": variant === "primary", "border bg-card text-foreground hover:bg-muted": variant === "secondary", "text-muted-foreground hover:bg-muted hover:text-foreground": variant === "ghost", "border border-input bg-card text-foreground hover:bg-muted": variant === "danger" }, className)} {...props} />;
}

export function Card({ className, ...props }: HTMLAttributes<HTMLDivElement>) { return <section className={cn("qrypton-card", className)} {...props} />; }
export function CardHeader({ className, ...props }: HTMLAttributes<HTMLDivElement>) { return <div className={cn("flex flex-col gap-2 p-6", className)} {...props} />; }
export function CardTitle({ className, children, ...props }: HTMLAttributes<HTMLHeadingElement>) { return <h2 className={cn("text-base font-semibold", className)} {...props}>{children}</h2>; }
export function CardContent({ className, ...props }: HTMLAttributes<HTMLDivElement>) { return <div className={cn("px-6 pb-6", className)} {...props} />; }
export function Badge({ className, children, ...props }: HTMLAttributes<HTMLSpanElement>) { return <span className={cn("qrypton-badge", className)} {...props}>{children}</span>; }

const riskMeta = {
  critical: { label: "Critical", Icon: CircleAlert },
  high: { label: "High", Icon: TriangleAlert },
  medium: { label: "Medium", Icon: Diamond },
  low: { label: "Low", Icon: Shield },
  safe: { label: "Safe", Icon: ShieldCheck },
  unknown: { label: "Unknown", Icon: CircleHelp },
  informational: { label: "Informational", Icon: Info },
  unassessed: { label: "Unassessed", Icon: CircleDashed },
} as const;

export type RiskLevel = keyof typeof riskMeta;

export function RiskBadge({ level, className, ...props }: Omit<HTMLAttributes<HTMLSpanElement>, "children"> & { level: string }) {
  const normalized: RiskLevel = Object.hasOwn(riskMeta, level) ? level as RiskLevel : "unknown";
  const { label, Icon } = riskMeta[normalized];
  return <span {...props} className={cn("qrypton-badge", `qrypton-risk-${normalized}`, className)} data-risk-level={normalized}><Icon className="size-3 shrink-0" aria-hidden="true" /><span>{label}</span></span>;
}
export function Input({ className, ...props }: InputHTMLAttributes<HTMLInputElement>) { return <input className={cn("h-10 w-full rounded-md border border-input bg-card px-4 text-sm text-foreground placeholder:text-muted-foreground focus:ring-2 focus:ring-primary", className)} {...props} />; }
export function Alert({ className, children, ...props }: HTMLAttributes<HTMLDivElement> & { children?: ReactNode }) { return <div role="alert" className={cn("flex items-start gap-4 rounded-md border bg-card p-4 text-sm", className)} {...props}>{children}</div>; }
