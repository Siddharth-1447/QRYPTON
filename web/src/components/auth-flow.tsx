"use client";

import { useState } from "react";
import { AlertCircle, ArrowRight, Check, Eye, EyeOff, LockKeyhole, ShieldCheck } from "lucide-react";
import { Alert, Badge, Button, Card, CardContent, CardHeader, CardTitle, Input } from "@/components/ui/primitives";
import { CryptoLockVisual } from "@/components/crypto-lock-visual";

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
  const [rememberMe, setRememberMe] = useState(true);

  const persistSession = () => {
    const storage = rememberMe ? window.localStorage : window.sessionStorage;
    storage.setItem("qrypton.session", "active");
    storage.setItem("qrypton.user", email.trim() || "security@qrypton.local");
  };

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
    persistSession();
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
                  <div key={`${step.label}-${index}`} className="rounded-lg border border-border bg-muted/40 p-4">
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
        <div className="hidden flex-col justify-between bg-primary p-10 text-primary-foreground lg:flex"><div><div className="mb-10 flex items-center gap-3"><div className="flex size-10 items-center justify-center rounded-lg bg-primary-foreground/15"><LockKeyhole aria-hidden="true" /></div><span className="text-lg font-semibold tracking-[0.12em]">QRYPTON</span></div><CryptoLockVisual compact /><p className="qrypton-kicker text-primary-foreground/70">Enterprise cryptographic security</p><h1 className="mt-3 max-w-sm text-4xl font-semibold tracking-tight">Know what is exposed. Know what to do next.</h1><p className="mt-5 max-w-sm text-sm leading-6 text-primary-foreground/75">A focused workspace for inventory, quantum risk posture, and migration planning.</p></div><p className="text-xs text-primary-foreground/65">Protected workspace access</p></div>
        <div className="p-6 sm:p-10"><div className="mb-8 flex items-center gap-3 lg:hidden"><div className="flex size-9 items-center justify-center rounded-lg bg-primary text-primary-foreground"><ShieldCheck aria-hidden="true" /></div><div><p className="font-semibold">QRYPTON</p><p className="qrypton-kicker">PQC command center</p></div></div><div className="mb-8"><p className="qrypton-kicker">Secure sign in</p><h1 className="mt-2 text-2xl font-semibold tracking-tight">Welcome back</h1><p className="mt-2 text-sm leading-6 text-muted-foreground">Sign in to review your organization&apos;s cryptographic posture.</p></div>
          <form className="flex flex-col gap-5" onSubmit={submitLogin} noValidate><label className="flex flex-col gap-2 text-sm font-medium" htmlFor="email">Work email<Input id="email" type="email" autoComplete="email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="you@company.com" aria-invalid={Boolean(error && (!email || !email.includes("@")))} /></label><label className="flex flex-col gap-2 text-sm font-medium" htmlFor="password">Password<div className="relative"><Input id="password" type={showPassword ? "text" : "password"} autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} className="pr-11" aria-invalid={Boolean(error && password.length < 8)} /><button type="button" aria-label={showPassword ? "Hide password" : "Show password"} className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground" onClick={() => setShowPassword((visible) => !visible)}>{showPassword ? <EyeOff aria-hidden="true" /> : <Eye aria-hidden="true" />}</button></div></label><label className="flex items-center gap-2 text-sm text-muted-foreground"><input type="checkbox" checked={rememberMe} onChange={(event) => setRememberMe(event.target.checked)} />Remember me on this device</label>{error && <Alert className="border-red-200 bg-red-50 text-red-800"><AlertCircle className="mt-0.5 shrink-0" aria-hidden="true" /><p className="text-sm leading-5">{error}</p></Alert>}{recoverySent && <Alert className="border-green-200 bg-green-50 text-green-800"><Check className="mt-0.5 shrink-0" aria-hidden="true" /><p className="text-sm leading-5">Recovery instructions were sent if an account exists for this email.</p></Alert>}<Button type="submit" disabled={loading}>{loading ? "Verifying access…" : "Sign in"}</Button></form>
          <div className="mt-6 flex flex-col gap-3">
            <div className="relative flex items-center py-2"><span className="flex-grow border-t border-border"></span><span className="mx-3 text-xs text-muted-foreground">or continue with</span><span className="flex-grow border-t border-border"></span></div>
            <button type="button" onClick={() => { setLoading(true); setTimeout(() => { persistSession(); setLoading(false); onComplete(); }, 600); }} className="inline-flex w-full items-center justify-center gap-3 rounded-md border border-border px-3 py-2.5 text-sm font-semibold text-foreground transition-colors hover:bg-muted">
              <svg className="h-5 w-5" viewBox="0 0 24 24" aria-hidden="true"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" fill="#4285F4"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/></svg>
              Sign in with Google
            </button>
            <button type="button" onClick={() => { setLoading(true); setTimeout(() => { persistSession(); setLoading(false); onComplete(); }, 600); }} className="inline-flex w-full items-center justify-center gap-3 rounded-md border border-border px-3 py-2.5 text-sm font-semibold text-foreground transition-colors hover:bg-muted">
              <svg className="h-5 w-5" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0 1 12 6.844a9.59 9.59 0 0 1 2.504.337c1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.02 10.02 0 0 0 22 12.017C22 6.484 17.522 2 12 2z"/></svg>
              Sign in with GitHub
            </button>
          </div>
          <div className="mt-6 flex items-center justify-between gap-4 text-sm"><button type="button" className="text-muted-foreground hover:text-foreground text-xs font-semibold" onClick={onComplete}>← Return to Public Dashboard</button><button type="button" className="font-semibold text-primary hover:underline text-xs" onClick={recoverAccess} disabled={loading}>Recover account</button></div><p className="mt-8 text-center text-xs leading-5 text-muted-foreground">Access is limited to authorized QRYPTON workspaces. Your session is protected by your organization&apos;s identity controls.</p>
        </div>
      </section>
    </main>
  );
}
