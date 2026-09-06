import type { ButtonHTMLAttributes, HTMLAttributes, InputHTMLAttributes, ReactNode } from "react";
import { cn } from "@/lib/utils";

export function Button({ className, variant = "primary", ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "ghost" | "danger" }) {
  return <button className={cn("inline-flex min-h-9 items-center justify-center gap-2 rounded-md px-3 text-sm font-semibold transition-colors disabled:pointer-events-none disabled:opacity-50", { "bg-primary text-primary-foreground hover:opacity-90": variant === "primary", "border bg-card text-foreground hover:bg-muted": variant === "secondary", "text-muted-foreground hover:bg-muted hover:text-foreground": variant === "ghost", "border border-red-200 bg-red-50 text-red-700 hover:bg-red-100": variant === "danger" }, className)} {...props} />;
}

export function Card({ className, ...props }: HTMLAttributes<HTMLDivElement>) { return <section className={cn("qrypton-card", className)} {...props} />; }
export function CardHeader({ className, ...props }: HTMLAttributes<HTMLDivElement>) { return <div className={cn("flex flex-col gap-1 p-5", className)} {...props} />; }
export function CardTitle({ className, children, ...props }: HTMLAttributes<HTMLHeadingElement>) { return <h2 className={cn("text-base font-semibold tracking-tight", className)} {...props}>{children}</h2>; }
export function CardContent({ className, ...props }: HTMLAttributes<HTMLDivElement>) { return <div className={cn("px-5 pb-5", className)} {...props} />; }
export function Badge({ className, tone = "info", children, ...props }: HTMLAttributes<HTMLSpanElement> & { tone?: "critical" | "high" | "medium" | "low" | "info" | "success" }) { return <span className={cn("inline-flex items-center rounded-full px-2 py-1 text-[11px] font-bold uppercase tracking-wide", `qrypton-risk-${tone}`, className)} {...props}>{children}</span>; }
export function Input({ className, ...props }: InputHTMLAttributes<HTMLInputElement>) { return <input className={cn("h-9 w-full rounded-md border bg-card px-3 text-sm text-foreground placeholder:text-muted-foreground focus:ring-2 focus:ring-blue-100", className)} {...props} />; }
export function Alert({ className, children, ...props }: HTMLAttributes<HTMLDivElement> & { children?: ReactNode }) { return <div role="alert" className={cn("flex items-start gap-3 rounded-md border bg-card p-4 text-sm", className)} {...props}>{children}</div>; }
