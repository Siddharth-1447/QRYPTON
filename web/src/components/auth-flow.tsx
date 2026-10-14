"use client";

import { useEffect, useRef, useState } from "react";
import { AlertCircle, ArrowRight, Eye, EyeOff, ShieldCheck } from "lucide-react";
import { Alert, Badge, Button, Card, CardContent, CardHeader, CardTitle, Input } from "@/components/ui/primitives";
import { Wordmark } from "@/components/logo";
import { HeroLogo } from "@/components/hero-logo";
import { API_BASE, workspaceRequest } from "@/lib/api";
import { ProviderIcon } from "./provider-icon";

type AuthScreen = "login" | "onboarding";
type Provider = "google" | "github" | "gitlab";

interface AuthFlowProps {
  onComplete: () => void;
}

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
  const [authConfig, setAuthConfig] = useState<{ providers: Record<Provider, boolean>; token_configured: boolean } | null>(null);
  const callbackStarted = useRef(false);
  const [rememberMe, setRememberMe] = useState(true);
  const [mode, setMode] = useState<"signin" | "signup" | "token">("signin");
  const [confirmPassword, setConfirmPassword] = useState("");

  const persistSession = (subject = "Viewer", signedInEmail?: string) => {
    for (const entry of [window.localStorage, window.sessionStorage]) for (const key of ["qrypton.session", "qrypton.user", "qrypton.email"]) entry.removeItem(key);
    const storage = rememberMe ? window.localStorage : window.sessionStorage;
    storage.setItem("qrypton.session", "active");
    storage.setItem("qrypton.user", subject);
    if (signedInEmail) storage.setItem("qrypton.email", signedInEmail);
    window.localStorage.setItem("qrypton.has_visited", "true");

  };

  const submitLogin = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError(null);

    if (!email.trim() || !email.includes("@")) {
      setError("Enter a valid email address.");
      return;
    }
    if (!password || (mode === "signup" && password.length < 12)) {
      setError("Enter your password (at least 12 characters for a new account).");
      return;
    }
    if (mode === "signup" && password !== confirmPassword) { setError("Passwords do not match."); return; }
    setLoading(true);
    try {
      if (mode !== "token") {
        const actor = await workspaceRequest<{ access_token: string; subject: string; role: string; email: string }>(`/auth/${mode}`, { method: "POST", body: JSON.stringify({ email: email.trim(), password }) });
        sessionStorage.setItem("qrypton.access-token", actor.access_token);
        sessionStorage.setItem("qrypton.role", actor.role);
        persistSession(actor.subject, actor.email);
        setPassword(""); setConfirmPassword(""); setScreen("onboarding"); return;
      }
      const response = await fetch(`${API_BASE}/api/v1/session`, {headers: {Authorization: `Bearer ${password}`}, signal: AbortSignal.timeout(10000)});
      if (!response.ok) throw new Error(response.status === 401 ? "This token is invalid. Use a token provisioned by your workspace administrator." : "The authentication service is unavailable. Check the backend connection.");
      const actor = await response.json();
      sessionStorage.setItem("qrypton.access-token", password);
      sessionStorage.setItem("qrypton.role", actor.role);
      persistSession(actor.subject, email.trim());
      setScreen("onboarding");
    } catch (cause) { setError(cause instanceof TypeError ? "Cannot connect to the authentication service. Check the backend connection." : cause instanceof Error ? cause.message : "Sign in failed"); }
    finally { setLoading(false); }
  };


  useEffect(() => {
    const controller = new AbortController();
    void workspaceRequest<typeof authConfig>("/auth/providers", { signal: AbortSignal.any([controller.signal, AbortSignal.timeout(8000)]) }).then(config => {
      if (!config?.providers || typeof config.token_configured !== "boolean") throw new Error("Invalid authentication configuration");
      setAuthConfig(config);
    }).catch(() => {
      if (!controller.signal.aborted) { setAuthConfig({ providers: { google: false, github: false, gitlab: false }, token_configured: false }); setError("Cannot connect to the authentication service. Check the backend connection."); }
    });
    return () => controller.abort();
  }, []);

  useEffect(() => {
    const params = new URLSearchParams(window.location.hash.slice(1));
    const code = params.get("auth_code");
    const failure = params.get("auth_error");
    if ((!code && !failure) || callbackStarted.current) return;
    callbackStarted.current = true;
    window.history.replaceState({}, "", window.location.pathname);
    if (failure) { queueMicrotask(() => setError(failure)); return; }
    const verifier = sessionStorage.getItem("qrypton.oauth-verifier");
    sessionStorage.removeItem("qrypton.oauth-verifier");
    if (!verifier) { queueMicrotask(() => setError("Sign-in expired. Please start again.")); return; }
    void workspaceRequest<{ access_token: string; subject: string; role: string; email?: string | null }>("/auth/exchange", { method: "POST", body: JSON.stringify({ code, verifier, origin: window.location.origin }) }).then(actor => {
      for (const entry of [window.localStorage, window.sessionStorage]) for (const key of ["qrypton.session", "qrypton.user", "qrypton.email"]) entry.removeItem(key);
      sessionStorage.setItem("qrypton.access-token", actor.access_token);
      sessionStorage.setItem("qrypton.role", actor.role);
      sessionStorage.setItem("qrypton.user", actor.subject);
      if (actor.email) sessionStorage.setItem("qrypton.email", actor.email);
      sessionStorage.setItem("qrypton.session", "active");
      localStorage.setItem("qrypton.has_visited", "true");
      setScreen("onboarding");
    }).catch(cause => setError(cause instanceof Error ? cause.message : "Sign-in failed."));
  }, []);

  const startProvider = async (provider: Provider) => {
    setLoading(true); setError(null);
    try {
      const verifier = Array.from(crypto.getRandomValues(new Uint8Array(32)), byte => byte.toString(16).padStart(2, "0")).join("");
      const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
      const challenge = btoa(String.fromCharCode(...digest)).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
      sessionStorage.setItem("qrypton.oauth-verifier", verifier);
      const result = await workspaceRequest<{ url: string }>(`/auth/${provider}/start`, { method: "POST", body: JSON.stringify({ origin: window.location.origin, challenge }) });
      window.location.assign(result.url);
    } catch (cause) { sessionStorage.removeItem("qrypton.oauth-verifier"); setError(cause instanceof Error ? cause.message : "Provider sign-in failed."); setLoading(false); }
  };

  const loadSample = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`${API_BASE}/api/v1/sample-workspace`, { method: "POST" });
      if (!response.ok) throw new Error("Sample workspace could not be loaded. Check the backend connection and retry.");
      onComplete();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Sample workspace could not be loaded.");
    } finally {
      setLoading(false);
    }
  };

  if (screen === "onboarding") {
    return (
      <main className="flex min-h-screen items-center justify-center bg-background px-4 py-10 sm:px-6">
        <section className="w-full max-w-3xl">
          <div className="mb-8 flex items-center gap-4">
            <div className="flex size-10 items-center justify-center rounded-lg bg-muted text-foreground"><ShieldCheck aria-hidden="true" /></div>
            <div><p className="text-lg font-semibold tracking-normal"><Wordmark /></p></div>
          </div>
          <Card>
            <CardHeader className="border-b border-border bg-card p-6 sm:p-8">
              <Badge className="w-fit">Workspace ready</Badge>
              <CardTitle className="pt-4 text-2xl sm:text-3xl">Start with Your Workspace’s Security Posture</CardTitle>
              <p className="max-w-2xl text-sm leading-6 text-muted-foreground">Connect assets, review cryptographic exposure, and plan migration from one workspace.</p>
            </CardHeader>
            <CardContent className="p-6 sm:p-8">
              <div className="grid gap-4 md:grid-cols-3">
                {steps.map((step, index) => (
                  <div key={`${step.label}-${index}`} className="rounded-lg border border-border bg-muted/40 p-4">
                    <div className="mb-4 flex items-center gap-2 text-secondary"><span className="flex size-7 items-center justify-center rounded-full bg-muted text-xs font-semibold text-foreground">{index + 1}</span><span className="text-sm font-semibold">{step.label}</span></div>
                    <p className="text-sm leading-6 text-muted-foreground">{step.label === "Assess" ? <><Wordmark /> maps algorithms, evidence, and risk.</> : step.description}</p>
                  </div>
                ))}
              </div>
              {error && <Alert className="mt-6 border-border" role="alert"><AlertCircle aria-hidden="true" /><p>{error}</p></Alert>}
              <div className="mt-8 flex flex-col gap-4 border-t border-border pt-6 sm:flex-row sm:items-center sm:justify-between"><Button variant="secondary" disabled={loading} onClick={() => { void loadSample(); }}>{loading ? "Loading sample workspace…" : "Try with sample payment app"}</Button><Button disabled={loading} onClick={onComplete}>Open command center <ArrowRight data-icon="inline-end" /></Button></div>
            </CardContent>
          </Card>
        </section>
      </main>
    );
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-background px-4 py-10 sm:px-6">
      <section className="grid w-full max-w-5xl overflow-hidden rounded-xl border border-border bg-card shadow-md lg:grid-cols-[0.9fr_1.1fr]">
        <div className="hidden flex-col justify-between bg-sidebar p-10 text-foreground lg:flex"><div><div className="mb-10 flex items-center gap-4"><Wordmark className="text-2xl font-semibold" /></div><HeroLogo compact spinOnMount={false} /><h1 className="mt-3 max-w-sm text-4xl font-semibold tracking-normal">Know What Is Exposed. Know What to Do Next.</h1><p className="mt-5 max-w-sm text-sm leading-6 text-secondary">A focused workspace for inventory, quantum risk posture, and migration planning.</p></div><p className="text-xs text-secondary">Protected workspace access</p></div>
        <div className="px-6 py-6 sm:px-10 sm:py-6">
          <div className="mb-6 lg:hidden"><Wordmark className="text-2xl font-semibold" /></div>
          <div className="mb-6 flex gap-2" role="group" aria-label="Account access">
            {(["signin", "signup"] as const).map(value => <Button key={value} type="button" variant={mode === value ? "primary" : "secondary"} aria-pressed={mode === value} disabled={loading} onClick={() => { setMode(value); setError(null); setPassword(""); setConfirmPassword(""); }}>{value === "signin" ? "Sign In" : "Sign Up"}</Button>)}
          </div>
          <h1 className="text-2xl font-semibold">{mode === "signup" ? "Create Your Account" : "Sign In"}</h1>
          <p className="mt-2 mb-5 text-sm text-muted-foreground">{mode === "signup" ? "Create an account to access your cryptographic assessment workspace." : "Welcome back. Sign in to continue your assessment."}</p>
          <form className="flex flex-col gap-4" onSubmit={submitLogin}>
            <label className="flex flex-col gap-2 text-sm font-medium" htmlFor="email">Email Address<Input id="email" type="email" autoComplete="username" required maxLength={254} value={email} onChange={event => setEmail(event.target.value)} placeholder="you@example.com" /></label>
            <label className="flex flex-col gap-2 text-sm font-medium" htmlFor="password">{mode === "token" ? "Workspace Access Token" : "Password"}<div className="relative"><Input id="password" type={showPassword ? "text" : "password"} autoComplete={mode === "signup" ? "new-password" : "current-password"} required minLength={mode === "signup" ? 12 : 1} maxLength={mode === "token" ? 4096 : 128} value={password} onChange={event => setPassword(event.target.value)} className="pr-11" /><button type="button" aria-label={showPassword ? "Hide password" : "Show password"} className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground" onClick={() => setShowPassword(!showPassword)}>{showPassword ? <EyeOff aria-hidden="true" /> : <Eye aria-hidden="true" />}</button></div></label>
            {mode === "signup" && <><p className="text-xs text-muted-foreground">Use at least 12 characters. New accounts have read-only access; your administrator manages additional permissions.</p><label className="flex flex-col gap-2 text-sm font-medium" htmlFor="confirm-password">Confirm Password<Input id="confirm-password" type={showPassword ? "text" : "password"} autoComplete="new-password" required maxLength={128} value={confirmPassword} onChange={event => setConfirmPassword(event.target.value)} /></label></>}
            <label className="flex items-center gap-2 text-sm text-muted-foreground"><input type="checkbox" checked={rememberMe} onChange={event => setRememberMe(event.target.checked)} />Remember me on this device</label>
            {error && <Alert role="alert"><AlertCircle className="shrink-0" aria-hidden="true" /><div>{error}{mode === "signin" && error.includes("Account not found") && <button type="button" className="mt-2 block text-primary underline" onClick={() => { setMode("signup"); setError(null); setPassword(""); }}>Create an account</button>}</div></Alert>}
            <Button type="submit" disabled={loading}>{loading ? "Please wait…" : mode === "signup" ? "Create Account" : "Sign In"}</Button>
          </form>
          <div className="my-5 flex items-center gap-3"><span className="flex-1 border-t border-border" /><span className="text-xs text-muted-foreground">OR</span><span className="flex-1 border-t border-border" /></div>
          <div className="flex flex-col gap-2">
            {(["google", "github"] as const).map(provider => <button key={provider} type="button" disabled={loading} onClick={() => void startProvider(provider)} className="inline-flex min-h-10 w-full items-center justify-center gap-3 rounded-md border border-border px-4 py-2.5 text-sm font-semibold qrypton-motion hover:bg-muted disabled:opacity-50"><ProviderIcon provider={provider} />Sign in with {provider === "google" ? "Google" : "GitHub"}</button>)}
          </div>
          {authConfig?.token_configured && <button type="button" className="mt-4 text-sm text-primary" onClick={() => { setMode(mode === "token" ? "signin" : "token"); setPassword(""); setError(null); }}>{mode === "token" ? "Use email and password" : "Use a workspace access token"}</button>}
          <Button type="button" variant="ghost" className="mt-4 w-full" onClick={() => { sessionStorage.removeItem("qrypton.access-token"); sessionStorage.setItem("qrypton.role", "Viewer"); persistSession(); setScreen("onboarding"); }}>Continue as read-only Viewer</Button>
        </div>
      </section>
    </main>
  );
}
