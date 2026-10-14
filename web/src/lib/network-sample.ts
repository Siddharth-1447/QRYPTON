export function networkSampleModeEnabled(value: string | undefined): boolean {
  return value === "1";
}

// Next.js replaces this direct public-environment reference at build time.
export const NETWORK_SAMPLE_MODE = networkSampleModeEnabled(
  process.env.NEXT_PUBLIC_QRYPTON_NETWORK_SAMPLE_MODE
);
