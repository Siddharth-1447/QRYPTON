"use client";

import { useEffect, useRef, useState } from "react";
import { Settings } from "lucide-react";
import { usePathname, useRouter } from "next/navigation";
import { Wordmark } from "./logo";
import { applyTheme, readThemeChoice, DEFAULT_THEME, THEME_STORAGE_KEY, type ThemeChoice } from "@/lib/theme";

const choices: Array<{ value: ThemeChoice; label: string; description: string }> = [
  { value: "light", label: "Light", description: "Use the light palette." },
  { value: "dark", label: "Dark", description: "Use the dark palette." },
  { value: "system", label: "System", description: "Follow your device appearance." },
];

export function ThemeSettings() {
  const router = useRouter();
  const onLoginPage = usePathname() === "/login";
  const [open, setOpen] = useState(false);
  const [choice, setChoice] = useState<ThemeChoice>(DEFAULT_THEME);
  const dialog = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const sync = () => {
      const current = readThemeChoice();
      applyTheme(current);
      setChoice(current);
    };
    const onStorage = (event: StorageEvent) => { if (event.key === THEME_STORAGE_KEY) sync(); };
    queueMicrotask(sync);
    media.addEventListener("change", sync);
    window.addEventListener("storage", onStorage);
    return () => { media.removeEventListener("change", sync); window.removeEventListener("storage", onStorage); };
  }, []);

  useEffect(() => { if (open) dialog.current?.showModal(); else dialog.current?.close(); }, [open]);

  return <>
    <button suppressHydrationWarning type="button" aria-label="Settings" title="Settings" className="grid size-10 shrink-0 place-items-center rounded-lg border border-border bg-card" onClick={() => setOpen(true)}><Settings className="size-5" aria-hidden="true" /></button>
    <dialog ref={dialog} onClose={() => setOpen(false)} onCancel={() => setOpen(false)} aria-labelledby="theme-settings-heading" className="productivity-dialog">
      <div className="flex items-start justify-between gap-4"><div><h2 id="theme-settings-heading" className="text-xl font-semibold">Settings</h2><p className="mt-1 text-sm text-muted-foreground">Choose how <Wordmark /> appears on this device.</p></div><button type="button" className="rounded border border-border px-3 py-2 text-sm" onClick={() => setOpen(false)}>Close</button></div>
      <fieldset className="mt-5 space-y-2"><legend className="mb-2 text-sm font-semibold">Theme</legend>{choices.map(option => <label key={option.value} className="flex cursor-pointer items-start gap-3 rounded-lg border border-border bg-card p-3 text-sm"><input type="radio" name="theme" value={option.value} checked={choice === option.value} onChange={() => { setChoice(option.value); applyTheme(option.value, true); }} className="mt-1 size-4 accent-primary" /><span><span className="block font-semibold">{option.label}</span><span className="block text-muted-foreground">{option.description}</span></span></label>)}</fieldset>
      {!onLoginPage && <button type="button" className="mt-5 rounded border border-border px-4 py-2 text-sm font-semibold" onClick={() => {
        for (const storage of [window.localStorage, window.sessionStorage]) for (const key of ["qrypton.session", "qrypton.user", "qrypton.email", "qrypton.access-token", "qrypton.role", "qrypton.oauth-verifier"]) storage.removeItem(key);
        setOpen(false);
        router.replace("/login");
      }}>Logout</button>}
    </dialog>
  </>;
}
