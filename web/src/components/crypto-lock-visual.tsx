"use client";

interface CryptoLockVisualProps {
  compact?: boolean;
  navbar?: boolean;
}

/** Existing product mark, kept static to reserve motion for user feedback. */
export function CryptoLockVisual({ compact = false, navbar = false }: CryptoLockVisualProps) {
  return (
    <div
      className={`crypto-cube-stage ${compact ? "crypto-cube-stage-compact" : ""} ${navbar ? "crypto-cube-stage-navbar" : ""}`}
      role="img"
      aria-label="QRYPTON cryptographic cube"
    >
      <svg viewBox="0 0 320 250" aria-hidden="true">
        <g className="crypto-cube-lines" fill="none" stroke="currentColor" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round">
          <path d="M181 31v100l81 47V78z" fill="currentColor" fillOpacity=".45" />
          <path d="M181 31 262 78l-81 47-81-47z" fill="currentColor" fillOpacity=".92" />
          <path d="M100 78v100l81 47v-100z" fill="currentColor" fillOpacity=".64" />
          <path d="m100 78 81 47 81-47M181 125v100" />
          <path d="M100 78 63 100M100 125l-37 22M100 172l-37 22M63 100H24M63 147H24M63 194H24" />
          <path d="m100 78-37 22m37 47-37 22m37 47-37 22" />
        </g>
        <g className="crypto-cube-nodes" fill="currentColor">
          <circle cx="100" cy="78" r="10" /><circle cx="100" cy="125" r="10" /><circle cx="100" cy="172" r="10" />
          <circle cx="63" cy="100" r="10" /><circle cx="63" cy="147" r="10" /><circle cx="63" cy="194" r="10" />
        </g>
      </svg>
    </div>
  );
}
