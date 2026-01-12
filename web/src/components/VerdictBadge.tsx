"use client";

import type { Verdict } from "@/types/scan";

type VerdictBadgeProps = {
  phase1Verdict?: Verdict | null;
  aiVerdict?: Verdict | null;
  className?: string;
};

function getVerdictStyles(verdict: Verdict | null | undefined): {
  bg: string;
  text: string;
  ring: string;
  label: string;
} {
  switch (verdict) {
    case "phishing":
      return { bg: "bg-rose-50", text: "text-rose-800", ring: "ring-rose-200", label: "Phishing" };
    case "needs_review":
      return { bg: "bg-amber-50", text: "text-amber-800", ring: "ring-amber-200", label: "Needs review" };
    case "benign":
      return { bg: "bg-emerald-50", text: "text-emerald-800", ring: "ring-emerald-200", label: "Benign" };
    default:
      return { bg: "bg-slate-50", text: "text-slate-700", ring: "ring-slate-200", label: "Pending" };
  }
}

export default function VerdictBadge({ phase1Verdict, aiVerdict, className = "" }: VerdictBadgeProps) {
  const activeVerdict = aiVerdict ?? phase1Verdict ?? null;
  const styles = getVerdictStyles(activeVerdict);
  const sublabel = aiVerdict ? "AI" : phase1Verdict ? "Phase‑1" : "";

  return (
    <div
      className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-sm font-medium ${styles.bg} ${styles.text} ring-1 ${styles.ring} ${className}`}
      aria-live="polite"
      aria-atomic
      role="status"
    >
      <span className="h-2 w-2 rounded-full bg-current opacity-70" aria-hidden />
      <span>{styles.label}</span>
      {sublabel && (
        <span className="ml-1 rounded-full bg-white/60 px-2 py-0.5 text-xs font-semibold text-slate-700 dark:text-slate-800">
          {sublabel}
        </span>
      )}
    </div>
  );
}


