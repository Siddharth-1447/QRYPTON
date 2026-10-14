"use client";

import { useEffect } from "react";

/** Reveal each section once without changing layout or hiding content from readers. */
export function SectionMotion() {
  useEffect(() => {
    const preference = matchMedia("(prefers-reduced-motion: reduce)");
    const observed = new WeakSet<Element>();
    const animations = new Set<Animation>();
    const observer = new IntersectionObserver(entries => {
      for (const entry of entries) {
        if (!entry.isIntersecting) continue;
        observer.unobserve(entry.target);
        if (preference.matches) continue;
        const animation = entry.target.animate([{ opacity: 0.5, transform: "translateY(8px)" }, { opacity: 1, transform: "translateY(0)" }], { duration: 240, easing: "ease-out" });
        animations.add(animation);
        animation.onfinish = () => animations.delete(animation);
      }
    }, { threshold: 0.05 });
    const observe = () => document.querySelectorAll("main section").forEach(section => {
      // Nested cards inherit their parent's entrance to avoid stacked movement.
      if (observed.has(section) || section.parentElement?.closest("section")) return;
      observed.add(section); observer.observe(section);
    });
    observe();
    const mutations = new MutationObserver(observe);
    mutations.observe(document.body, { childList: true, subtree: true });
    const cancel = () => { if (preference.matches) { animations.forEach(animation => animation.cancel()); animations.clear(); } };
    preference.addEventListener("change", cancel);
    return () => { observer.disconnect(); mutations.disconnect(); animations.forEach(animation => animation.cancel()); preference.removeEventListener("change", cancel); };
  }, []);
  return null;
}
