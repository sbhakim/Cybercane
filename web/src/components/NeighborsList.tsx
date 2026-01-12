"use client";

import * as React from "react";
import type { Neighbor } from "@/types/scan";

type NeighborsListProps = {
  neighbors?: Neighbor[] | null;
  className?: string;
  loading?: boolean;
  error?: string | null;
};

// removed unused labelStyle to satisfy linter

export default function NeighborsList({ neighbors, className = "", loading = false, error }: NeighborsListProps) {
  const items = (neighbors ?? []).slice(0, 8);
  const phish = items.filter((n) => n.label === 1);
  const topSimilarity = items[0]?.similarity ?? 0;
  const avgTop3Phish = phish.slice(0, 3).reduce((sum, n) => sum + n.similarity, 0) / Math.max(1, Math.min(3, phish.length));
  const [expanded, setExpanded] = React.useState<Record<number, boolean>>({});

  function toggle(id: number) {
    setExpanded((prev) => ({ ...prev, [id]: !prev[id] }));
  }

  return (
    <section className={`rounded-2xl border bg-white/60 dark:bg-slate-900/40 backdrop-blur p-6 shadow-sm ${className}`} aria-labelledby="neighbors-title">
      <h2 id="neighbors-title" className="text-lg font-semibold mb-4">Nearest Neighbors</h2>

      {loading && (
        <div className="space-y-3 animate-pulse">
          <div className="h-4 w-36 rounded bg-slate-200" />
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="h-10 rounded bg-slate-200" />
          ))}
        </div>
      )}

      {error && !loading && (
        <div role="alert" className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-800">
          {error}
        </div>
      )}

      {!neighbors && !loading && !error && (
        <p className="text-sm text-slate-600 dark:text-slate-300">Run AI analysis to see similar emails.</p>
      )}

      {items.length > 0 && !loading && !error && (
        <div className="space-y-4">
          <div className="grid grid-cols-3 gap-2 text-xs text-slate-600">
            <div><span className="font-medium text-slate-800">Phish neighbors:</span> {phish.length}</div>
            <div><span className="font-medium text-slate-800">Top similarity:</span> {topSimilarity.toFixed(2)}</div>
            <div><span className="font-medium text-slate-800">Avg top‑3 phish:</span> {isFinite(avgTop3Phish) ? avgTop3Phish.toFixed(2) : "0.00"}</div>
          </div>

          <ul role="list" className="space-y-2">
            {items.map((n) => {
              const isExpanded = !!expanded[n.id];
              const subjectText = n.subject && n.subject.trim().length > 0 ? n.subject : "(no subject)";
              const detailId = `neighbor-${n.id}-details`;
              const displayBody = n.body && n.body.length > 1200 ? `${n.body.slice(0, 1200)}…` : n.body;
              return (
                <li key={n.id} className="rounded-lg border p-3">
                  <div className="flex items-center justify-between gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="h-2 w-full rounded-full bg-slate-200">
                        <div
                          className={`h-2 rounded-full ${n.label === 1 ? "bg-rose-500" : n.label === 0 ? "bg-emerald-500" : "bg-slate-400"}`}
                          style={{ width: `${Math.max(0, Math.min(1, n.similarity)) * 100}%` }}
                          aria-hidden
                        />
                      </div>
                      <p className="mt-1 truncate text-sm text-slate-900 dark:text-slate-100" title={subjectText}>
                        {subjectText}
                      </p>
                      <button
                        type="button"
                        onClick={() => toggle(n.id)}
                        className="mt-2 text-left text-sm text-blue-600 hover:text-blue-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400"
                        aria-expanded={isExpanded}
                        aria-controls={detailId}
                      >
                        {isExpanded ? "Hide email context" : "View email context"}
                      </button>
                      {isExpanded && (
                        <div id={detailId} className="mt-2 space-y-2">
                          <div className="rounded-md border bg-white/70 px-3 py-2 text-sm text-slate-900 dark:border-slate-700 dark:bg-slate-800/60 dark:text-slate-100 whitespace-pre-wrap">
                            {displayBody && displayBody.trim().length > 0 ? displayBody : "No body available"}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </li>
              );
            })}
          </ul>
        </div>
      )}
    </section>
  );
}


