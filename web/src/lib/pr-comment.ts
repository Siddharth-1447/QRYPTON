export type IntroducedFinding = { finding_id: string; label: string; severity: string; href: string };
export type CommentResult = {
  title: string; result: string; gate_effect: "blocks" | "warns" | "not_evaluated";
  introduced: IntroducedFinding[];
};

export function formatPrComment(result: CommentResult, origin: string): string {
  const introduced = result.introduced.length
    ? result.introduced.map(item => `- **${item.severity.toUpperCase()}** ${item.label} — [full finding](${new URL(item.href, origin).href})`).join("\n")
    : "- No introduced findings were reported for this CI result.";
  const gate = result.gate_effect === "blocks" ? "Blocks merge" : result.gate_effect === "warns" ? "Warns only" : "Not evaluated by the CI publisher";
  return `### QRYPTON crypto scan · ${result.title}\nResult: **${result.result}** · Policy gate: **${gate}**\n\nIntroduced findings:\n${introduced}`;
}
