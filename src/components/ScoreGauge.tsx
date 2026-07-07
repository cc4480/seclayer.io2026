import React, { useEffect, useRef, useState } from 'react';
import type { Grade } from '../../server/scoring.js';
import { GRADE_ACCENT } from '../lib/severity.js';

interface ScoreGaugeProps {
  score: number;   // 0-100
  grade: Grade;
  size?: number;   // px, default 132
}

// Small easing so the count-up and arc-draw feel intentional, not linear.
const easeOut = (t: number) => 1 - Math.pow(1 - t, 3);

// A 270° radial gauge: a recessive track with a grade-coloured progress arc that
// draws on mount, and a hero number that counts up to the score. The arc colour
// comes from the grade band (GRADE_ACCENT) so it always agrees with the letter.
export default function ScoreGauge({ score, grade, size = 132 }: ScoreGaugeProps) {
  const clamped = Math.max(0, Math.min(100, score));
  const accent = GRADE_ACCENT[grade];

  const r = 42;
  const c = 2 * Math.PI * r;
  const arcFraction = 0.75; // 270°
  const arcLen = c * arcFraction;
  const targetOffset = arcLen - arcLen * (clamped / 100);

  // Count-up number (respects reduced-motion by snapping).
  const [display, setDisplay] = useState(0);
  const [offset, setOffset] = useState(arcLen); // start empty, animate to targetOffset
  const raf = useRef<number | undefined>(undefined);

  useEffect(() => {
    const reduce = typeof window !== 'undefined'
      && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
    if (reduce) {
      setDisplay(clamped);
      setOffset(targetOffset);
      return;
    }
    const dur = 900;
    const start = performance.now();
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / dur);
      const e = easeOut(t);
      setDisplay(Math.round(clamped * e));
      setOffset(arcLen - (arcLen - targetOffset) * e);
      if (t < 1) raf.current = requestAnimationFrame(tick);
    };
    raf.current = requestAnimationFrame(tick);
    return () => { if (raf.current) cancelAnimationFrame(raf.current); };
  }, [clamped, targetOffset, arcLen]);

  return (
    <div className="relative shrink-0" style={{ width: size, height: size }} aria-label={`Score ${clamped} of 100, grade ${grade}`}>
      <svg viewBox="0 0 100 100" width={size} height={size} className="block">
        {/* recessive track (270°) */}
        <circle
          cx="50" cy="50" r={r} fill="none"
          stroke="#27272a" strokeWidth="7" strokeLinecap="round"
          strokeDasharray={`${arcLen} ${c}`}
          transform="rotate(135 50 50)"
        />
        {/* grade-coloured progress arc */}
        <circle
          cx="50" cy="50" r={r} fill="none"
          stroke={accent.hex} strokeWidth="7" strokeLinecap="round"
          strokeDasharray={`${arcLen} ${c}`}
          strokeDashoffset={offset}
          transform="rotate(135 50 50)"
          style={{ filter: `drop-shadow(0 0 4px ${accent.hex}55)` }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center select-none">
        <div className="flex items-baseline">
          <span className={`font-mono font-black leading-none ${accent.text}`} style={{ fontSize: size * 0.3 }}>{display}</span>
          <span className="font-mono text-[#52525b] text-xs ml-0.5">/100</span>
        </div>
        <span className={`font-mono font-bold uppercase tracking-widest mt-1 ${accent.text}`} style={{ fontSize: size * 0.085 }}>
          Grade {grade}
        </span>
      </div>
    </div>
  );
}
