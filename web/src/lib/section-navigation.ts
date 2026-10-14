export type SectionPosition = { id: string; top: number };

/** Use document position, including nested anchors, rather than nav list order. */
export function sectionAtScrollPosition(
  sections: readonly SectionPosition[],
  activationLine = 120,
  atBottom = false,
): string {
  const ordered = [...sections].sort((a, b) => a.top - b.top);
  if (atBottom && ordered.length) return ordered[ordered.length - 1].id;
  return ordered.filter((section) => section.top <= activationLine).at(-1)?.id ?? "dashboard";
}
