"use client";

import VerdictBadge from "./VerdictBadge";
import type { AIAnalyzeOut } from "@/types/scan";

type AIInsightsCardProps = {
  data?: Pick<AIAnalyzeOut, "ai_verdict" | "ai_reasons"> | null;
  loading?: boolean;
  error?: string | null;
  className?: string;
};

export default function AIInsightsCard({ data, loading = false, error, className = "" }: AIInsightsCardProps) {
  return (
    <section className={`rounded-2xl border bg-white/60 dark:bg-slate-900/40 backdrop-blur p-6 shadow-sm ${className}`} aria-labelledby="ai-title">
      <h2 id="ai-title" className="text-lg font-semibold mb-4">AI Insights</h2>
      <p className="text-xs text-slate-500 mb-3">Nearest neighbors are <strong>phishing-only</strong> (label=1) and used for RAG context.</p>

      {loading && (
        <div className="space-y-3 animate-pulse">
          <div className="h-4 w-28 rounded bg-slate-200" />
          <div className="h-2 w-full rounded bg-slate-200" />
          <div className="h-2 w-5/6 rounded bg-slate-200" />
          <div className="h-2 w-3/6 rounded bg-slate-200" />
        </div>
      )}

      {error && !loading && (
        <div role="alert" className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-800">
          {error}
        </div>
      )}

      {!data && !loading && !error && (
        <p className="text-sm text-slate-600 dark:text-slate-300">Run the AI analysis for model consensus and context.</p>
      )}

      {data && !loading && !error && (
        <div className="space-y-3">
          {data.ai_verdict !== "benign" && <VerdictBadge aiVerdict={data.ai_verdict} />}
          {Array.isArray(data.ai_reasons) && data.ai_reasons.length > 0 && (
            <ul className="list-disc pl-5 text-sm text-slate-700 dark:text-slate-300">
              {(() => {
                const reasons = data.ai_reasons;
                const items = reasons.length <= 5 ? reasons : [...reasons.slice(0, 4), reasons[reasons.length - 1]];
                return items.map((r, i) => {
                const isConclusion = /^Conclusion:\s+\*\*(PHISH|LEGIT)\*\*/i.test(r);
                return (
                  <li key={i} className={`line-clamp-2 ${isConclusion ? "font-semibold" : ""}`} title={r}>
                    {/* render minimal markdown for **bold** only */}
                    {isConclusion ? (
                      <span dangerouslySetInnerHTML={{ __html: r.replace(/\*\*(.*?)\*\*/g, '<strong>$1<\/strong>') }} />
                    ) : (
                      r
                    )}
                  </li>
                );
              });
              })()}
            </ul>
          )}
        </div>
      )}
    </section>
  );
}


