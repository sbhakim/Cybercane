"use client";

import { useState } from "react";

type Redactions = { types: Record<string, number>; count: number };

type RedactionsPanelProps = {
  redactions?: Redactions | null;
  redactedBody?: string | null;
  rawBody?: string | null;
  className?: string;
  loading?: boolean;
  error?: string | null;
};

export default function RedactionsPanel({ redactions, redactedBody, rawBody, className = "", loading = false, error }: RedactionsPanelProps) {
  return (
    <section className={`rounded-2xl border bg-white/60 dark:bg-slate-900/40 backdrop-blur p-6 shadow-sm ${className}`} aria-labelledby="redact-title">
      <h2 id="redact-title" className="text-lg font-semibold mb-4">PII Redactions</h2>

      {loading && (
        <div className="space-y-3 animate-pulse">
          <div className="h-4 w-40 rounded bg-slate-200" />
          <div className="h-24 w-full rounded bg-slate-200" />
        </div>
      )}

      {error && !loading && (
        <div role="alert" className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-800">
          {error}
        </div>
      )}

      {!redactions && !loading && !error && (
        <p className="text-sm text-slate-600 dark:text-slate-300">Run a scan to view redaction details.</p>
      )}

      {redactions && !loading && !error && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
            <div className="rounded-md border bg-white/50 p-2 text-sm">
              <div className="text-xs uppercase tracking-wide text-slate-500">Total</div>
              <div className="font-medium text-slate-900 dark:text-slate-100">{redactions.count}</div>
            </div>
            {Object.entries(redactions.types || {}).map(([k, v]) => (
              <div key={k} className="rounded-md border bg-white/50 p-2 text-sm">
                <div className="text-xs uppercase tracking-wide text-slate-500">{k}</div>
                <div className="font-medium text-slate-900 dark:text-slate-100">{v}</div>
              </div>
            ))}
          </div>

          <Tabs redacted={redactedBody ?? ""} raw={rawBody ?? ""} />
        </div>
      )}
    </section>
  );
}

function Tabs({ redacted, raw }: { redacted: string; raw: string }) {
  const hasRedacted = redacted && redacted.trim().length > 0;
  const hasRaw = raw && raw.trim().length > 0;
  const [active, setActive] = useState<"redacted" | "raw">(hasRedacted ? "redacted" : "raw");
  return (
    <div>
      <div role="tablist" aria-label="Body view" className="mb-2 inline-flex rounded-lg border bg-white/60 p-0.5">
        <button
          role="tab"
          aria-selected={active === "redacted"}
          className={`px-3 py-1.5 text-sm rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400 ${active === "redacted" ? "bg-slate-100" : ""}`}
          onClick={() => setActive("redacted")}
        >
          Redacted
        </button>
        <button
          role="tab"
          aria-selected={active === "raw"}
          className={`px-3 py-1.5 text-sm rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400 ${active === "raw" ? "bg-slate-100" : ""}`}
          onClick={() => setActive("raw")}
        >
          Raw
        </button>
      </div>
      <div role="tabpanel" className="rounded-md border bg-white/70 p-3 text-sm text-slate-800 dark:text-slate-200 ctf-scrollable max-h-64 whitespace-pre-wrap">
        {active === "redacted" ? (hasRedacted ? redacted : "(empty)") : hasRaw ? raw : "(empty)"}
      </div>
    </div>
  );
}


