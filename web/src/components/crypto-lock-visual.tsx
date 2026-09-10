"use client";

import { useState } from "react";

interface CryptoLockVisualProps {
  compact?: boolean;
  navbar?: boolean;
}

/** Minimal cryptographic-cube mark, cursor-responsive without a raster/WebGL dependency. */
export function CryptoLockVisual({ compact = false, navbar = false }: CryptoLockVisualProps) {
  const [rotation, setRotation] = useState({ x: 0, y: 0 });
  return (
    <div
      className={`crypto-cube-stage ${compact ? "crypto-cube-stage-compact" : ""} ${navbar ? "crypto-cube-stage-navbar" : ""}`}
      onMouseMove={(event) => {
        const box = event.currentTarget.getBoundingClientRect();
        setRotation({ x: ((event.clientY - box.top) / box.height - .5) * -15, y: ((event.clientX - box.left) / box.width - .5) * 18 });
      }}
      onMouseLeave={() => setRotation({ x: 0, y: 0 })}
      role="img"
      aria-label="Interactive cryptographic cube visual"
    >
      <svg viewBox="0 0 320 250" aria-hidden="true" style={{ transform: `rotateX(${rotation.x}deg) rotateY(${rotation.y}deg)` }}>
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
