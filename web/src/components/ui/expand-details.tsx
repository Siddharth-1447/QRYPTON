"use client";

import { useId, useState, type ReactNode } from "react";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import { ChevronDown } from "lucide-react";

/** Full-width content disclosure: preserves table space and keyboard focus. */
export function ExpandDetails({ title, children }: { title: string; children: ReactNode }) {
  const [open, setOpen] = useState(true);
  const id = useId();
  const reduced = useReducedMotion();
  return <div className="min-w-0">
    <button type="button" aria-expanded={open} aria-controls={id} onClick={() => setOpen(!open)} className="flex items-center gap-2 rounded py-2 text-sm font-medium focus-visible:outline-2 focus-visible:outline-primary">
      <motion.span animate={{ rotate: open ? 0 : -90 }} transition={{ duration: reduced ? 0 : 0.2 }}><ChevronDown className="size-4" /></motion.span>{title}
    </button>
    <AnimatePresence initial={false}>
      {open && <motion.div key="content" id={id} initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }} exit={{ height: 0, opacity: 0 }} transition={reduced ? { duration: 0 } : { type: "spring", stiffness: 200, damping: 26, mass: 1 }} className="overflow-hidden">
        <div className="space-y-4 py-2">{children}</div>
      </motion.div>}
    </AnimatePresence>
  </div>;
}
