"use client";

import { useState } from "react";
import { AlertCircle, ArrowRight, Check, Eye, EyeOff, LockKeyhole, ShieldCheck } from "lucide-react";
import { Alert, Badge, Button, Card, CardContent, CardHeader, CardTitle, Input } from "@/components/ui/primitives";

type AuthScreen = "login" | "onboarding";

interface AuthFlowProps {
  onComplete: () => void;
}

const devAuthRedirect = process.env.NEXT_PUBLIC_DEV_SUPABASE_REDIRECT_URL || "#";

const steps = [
  { label: "Connect", description: "Bring in repositories and runtime assets." },
  { label: "Assess", description: "QRYPTON maps algorithms, evidence, and risk." },
  { label: "Plan", description: "Turn findings into a migration roadmap." },
];

export function AuthFlow({ onComplete }: AuthFlowProps) {
  const [screen, setScreen] = useState<AuthScreen>("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [recoverySent, setRecoverySent] = useState(false);

  const submitLogin = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError(null);
    setRecoverySent(false);
    if (!email.trim() || !email.includes("@")) {
      setError("Enter a valid work email address.");
      return;
    }
    if (password.length < 8) {
      setError("Password must be at least 8 characters.");
      return;
    }
    setLoading(true);
    await new Promise((resolve) => setTimeout(resolve, 850));
    setLoading(false);
    setScreen("onboarding");
  };

  const recoverAccess = async () => {
    if (!email.trim() || !email.includes("@")) {
      setError("Enter your work email first so we can send recovery instructions.");
      return;
    }
    setLoading(true);
    setError(null);
    await new Promise((resolve) => setTimeout(resolve, 700));
    setLoading(false);
    setRecoverySent(true);
  };

  if (screen === "onboarding") {
    return (
      <main className="flex min-h-screen items-center justify-center bg-background px-4 py-10 sm:px-6">
        <section className="w-full max-w-3xl">
          <div className="mb-8 flex items-center gap-3">
            <div className="flex size-10 items-center justify-center rounded-lg bg-primary text-primary-foreground"><ShieldCheck aria-hidden="true" /></div>
            <div><p className="text-lg font-semibold tracking-tight">QRYPTON</p><p className="qrypton-kicker">PQC command center</p></div>
          </div>
          <Card>
            <CardHeader className="border-b border-border bg-card p-6 sm:p-8">
              <Badge tone="success" className="w-fit">Workspace ready</Badge>
              <CardTitle className="pt-3 text-2xl sm:text-3xl">Start with your security posture</CardTitle>
              <p className="max-w-2xl text-sm leading-6 text-muted-foreground">QRYPTON helps your team move from cryptographic inventory to an evidence-backed migration plan. You can connect a source, review exposure, and assign next actions from one workspace.</p>
            </CardHeader>
            <CardContent className="p-6 sm:p-8">
              <div className="grid gap-3 md:grid-cols-3">
                {steps.map((step, index) => (
                  <div key={step.label} className="rounded-lg border border-border bg-muted/40 p-4">
                    <div className="mb-4 flex items-center gap-2 text-primary"><span className="flex size-7 items-center justify-center rounded-full bg-primary text-xs font-bold text-primary-foreground">{index + 1}</span><span className="text-sm font-semibold">{step.label}</span></div>
                    <p className="text-sm leading-6 text-muted-foreground">{step.description}</p>
                  </div>
                ))}
              </div>
              <div className="mt-8 flex flex-col gap-3 border-t border-border pt-6 sm:flex-row sm:items-center sm:justify-between"><p className="text-sm text-muted-foreground">You can change these connections and settings later.</p><Button onClick={onComplete}>Open command center <ArrowRight data-icon="inline-end" /></Button></div>
            </CardContent>
          </Card>
        </section>
      </main>
    );
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-background px-4 py-10 sm:px-6">
      <section className="grid w-full max-w-5xl overflow-hidden rounded-xl border border-border bg-card shadow-md lg:grid-cols-[0.9fr_1.1fr]">
        <div className="hidden flex-col justify-between bg-primary p-10 text-primary-foreground lg:flex"><div><div className="mb-12 flex items-center gap-3"><div className="flex size-10 items-center justify-center rounded-lg bg-primary-foreground/15"><LockKeyhole aria-hidden="true" /></div><span className="text-lg font-semibold tracking-tight">QRYPTON</span></div><p className="qrypton-kicker text-primary-foreground/70">Enterprise cryptographic security</p><h1 className="mt-3 max-w-sm text-4xl font-semibold tracking-tight">Know what is exposed. Know what to do next.</h1><p className="mt-5 max-w-sm text-sm leading-6 text-primary-foreground/75">A focused workspace for inventory, quantum risk posture, and migration planning.</p></div><p className="text-xs text-primary-foreground/65">Protected workspace access</p></div>
        <div className="p-6 sm:p-10"><div className="mb-8 flex items-center gap-3 lg:hidden"><div className="flex size-9 items-center justify-center rounded-lg bg-primary text-primary-foreground"><ShieldCheck aria-hidden="true" /></div><div><p className="font-semibold">QRYPTON</p><p className="qrypton-kicker">PQC command center</p></div></div><div className="mb-8"><p className="qrypton-kicker">Secure sign in</p><h1 className="mt-2 text-2xl font-semibold tracking-tight">Welcome back</h1><p className="mt-2 text-sm leading-6 text-muted-foreground">Sign in to review your organization&apos;s cryptographic posture.</p></div>
          <form className="flex flex-col gap-5" onSubmit={submitLogin} noValidate><label className="flex flex-col gap-2 text-sm font-medium" htmlFor="email">Work email<Input id="email" type="email" autoComplete="email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="you@company.com" aria-invalid={Boolean(error && (!email || !email.includes("@")))} /></label><label className="flex flex-col gap-2 text-sm font-medium" htmlFor="password">Password<div className="relative"><Input id="password" type={showPassword ? "text" : "password"} autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} className="pr-11" aria-invalid={Boolean(error && password.length < 8)} /><button type="button" aria-label={showPassword ? "Hide password" : "Show password"} className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground" onClick={() => setShowPassword((visible) => !visible)}>{showPassword ? <EyeOff aria-hidden="true" /> : <Eye aria-hidden="true" />}</button></div></label>{error && <Alert className="border-red-200 bg-red-50 text-red-800"><AlertCircle className="mt-0.5 shrink-0" aria-hidden="true" /><p className="text-sm leading-5">{error}</p></Alert>}{recoverySent && <Alert className="border-green-200 bg-green-50 text-green-800"><Check className="mt-0.5 shrink-0" aria-hidden="true" /><p className="text-sm leading-5">Recovery instructions were sent if an account exists for this email.</p></Alert>}<Button type="submit" disabled={loading}>{loading ? "Verifying access…" : "Sign in"}</Button></form>
          <a href={devAuthRedirect} className="mt-4 inline-flex w-full items-center justify-center rounded-md border border-border px-3 py-2 text-sm font-semibold text-foreground transition-colors hover:bg-muted">Use organization sign-in</a>
          <div className="mt-6 flex items-center justify-between gap-4 text-sm"><span className="text-muted-foreground">Need access?</span><button type="button" className="font-semibold text-primary hover:underline" onClick={recoverAccess} disabled={loading}>Recover account</button></div><p className="mt-8 text-center text-xs leading-5 text-muted-foreground">Access is limited to authorized QRYPTON workspaces. Your session is protected by your organization&apos;s identity controls.</p>
        </div>
      </section>
    </main>
  );
}
