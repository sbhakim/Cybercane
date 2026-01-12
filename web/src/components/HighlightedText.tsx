"use client";

import * as React from "react";

export type HighlightRange = { start: number; end: number; strength: "partial" | "strong" };

export default function HighlightedText({
  text,
  ranges,
  className,
}: {
  text: string;
  ranges: HighlightRange[];
  className?: string;
}) {
  const normalized = React.useMemo(() => {
    const valid = (ranges || [])
      .filter((r) => Number.isFinite(r.start) && Number.isFinite(r.end) && r.end > r.start)
      .sort((a, b) => a.start - b.start);
    const merged: HighlightRange[] = [];
    for (const r of valid) {
      const last = merged[merged.length - 1];
      if (last && r.start <= last.end) {
        // overlap -> extend with stronger strength if any
        last.end = Math.max(last.end, r.end);
        if (r.strength === "strong") last.strength = "strong";
      } else {
        merged.push({ ...r });
      }
    }
    return merged;
  }, [ranges]);

  const parts: React.ReactNode[] = [];
  let cursor = 0;
  for (const r of normalized) {
    if (cursor < r.start) {
      parts.push(text.slice(cursor, r.start));
    }
    const segment = text.slice(r.start, Math.min(text.length, r.end));
    const color = r.strength === "strong" ? "bg-yellow-400/60" : "bg-yellow-200/70 dark:bg-yellow-300/40";
    parts.push(
      <mark key={`${r.start}-${r.end}`} className={`rounded-sm ${color}`}> 
        {segment}
      </mark>
    );
    cursor = r.end;
  }
  if (cursor < text.length) parts.push(text.slice(cursor));

  return (
    <pre className={`whitespace-pre-wrap font-sans ${className ?? ""}`}>{parts}</pre>
  );
}


