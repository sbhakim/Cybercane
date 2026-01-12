"use client";

import ProgressBar from "./ProgressBar";
import type { ScanResponse } from "@/types/scan";

type Phase1CardProps = {
  data?: ScanResponse | null;
  loading?: boolean;
  error?: string | null;
  className?: string;
};

export default function Phase1Card({ data, loading = false, error, className = "" }: Phase1CardProps) {
  return (
    <section className={`rounded-2xl border bg-white/60 dark:bg-slate-900/40 backdrop-blur p-6 shadow-sm ${className}`} aria-labelledby="phase1-title">
      <h2 id="phase1-title" className="text-lg font-semibold mb-4">Phase‑1 Deterministic</h2>

      {loading && (
        <div className="space-y-3 animate-pulse">
          <div className="h-4 w-32 rounded bg-slate-200" />
          <div className="h-2 w-full rounded bg-slate-200" />
          <div className="h-2 w-5/6 rounded bg-slate-200" />
          <div className="h-2 w-4/6 rounded bg-slate-200" />
        </div>
      )}

      {error && !loading && (
        <div role="alert" className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-800">
          {error}
        </div>
      )}

      {!data && !loading && !error && (
        <p className="text-sm text-slate-600 dark:text-slate-300">Submit the form to see deterministic analysis.</p>
      )}

      {data && !loading && !error && (
        <div className="space-y-4">
          <ProgressBar label="Danger" value={data.score} max={10} color={data.verdict === "phishing" ? "red" : data.verdict === "needs_review" ? "yellow" : "green"} showPercentage={false} />

          {data.reasons?.length > 0 && (
            <div>
              <h3 className="text-sm font-semibold mb-2">Reasons</h3>
              <ul className="list-disc pl-5 text-sm text-slate-700 dark:text-slate-300">
                {data.reasons.map((r, i) => (
                  <li key={i} title={r} className="line-clamp-2">{r}</li>
                ))}
              </ul>
            </div>
          )}

          <div>
            <h3 className="text-sm font-semibold mb-2">Indicators</h3>
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="rounded-lg border p-3">
                <p className="text-xs uppercase tracking-wide text-slate-500">Sender domain</p>
                <p className="text-sm font-medium text-slate-900 dark:text-slate-100">
                  {(() => {
                    const val = (data.indicators as Record<string, unknown>)["sender_domain"];
                    return typeof val === "string" && val.trim() ? val : "—";
                  })()}
                </p>
              </div>
              <div className="rounded-lg border p-3 h-40 overflow-hidden flex flex-col">
                <p className="text-xs uppercase tracking-wide text-slate-500">Link hosts</p>
                <div className="mt-1 flex-1 overflow-y-auto pr-1 flex flex-wrap gap-1.5 content-start">
                  {(() => {
                    const val = (data.indicators as Record<string, unknown>)["link_hosts"];
                    const arr = Array.isArray(val) ? val.filter((v): v is string => typeof v === "string") : [];
                    return arr.length > 0 ? (
                      arr.map((h, i) => (
                      <span key={`${h}-${i}`} className="inline-flex items-center rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 text-xs text-slate-700">
                        {h}
                      </span>
                      ))
                    ) : (
                      <span className="text-sm text-slate-500">—</span>
                    );
                  })()}
                </div>
              </div>
              <div className="rounded-lg border p-3 sm:col-span-2">
                <p className="text-xs uppercase tracking-wide text-slate-500">Auth (DNS)</p>
                <div className="mt-1 grid grid-cols-2 gap-2 md:grid-cols-4">
                  {(() => {
                    const ind = data.indicators as Record<string, unknown>;
                    return (
                      <>
                        <KeyVal label="has_mx" value={ind["has_mx"]} />
                        <KeyVal label="spf_present" value={ind["spf_present"]} />
                        <KeyVal label="dmarc_present" value={ind["dmarc_present"]} />
                        {ind["dmarc_policy"] != null && (
                          <KeyVal label="dmarc_policy" value={ind["dmarc_policy"]} />
                        )}
                      </>
                    );
                  })()}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}

function KeyVal({ label, value }: { label: string; value: unknown }) {
  const v = value === true ? "yes" : value === false ? "no" : value ?? "—";
  return (
    <div className="rounded-md border bg-white/50 p-2 text-sm">
      <div className="text-xs uppercase tracking-wide text-slate-500">{label}</div>
      <div className="font-medium text-slate-900 dark:text-slate-100" title={String(v)}>
        {String(v)}
      </div>
    </div>
  );
}


