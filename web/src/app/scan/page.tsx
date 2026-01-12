"use client";

import * as React from "react";
import ScanForm from "@/components/ScanForm";
import ScanStepper from "@/components/ScanStepper";
import Phase1Card from "@/components/Phase1Card";
import AIInsightsCard from "@/components/AIInsightsCard";
import NeighborsList from "@/components/NeighborsList";
import RedactionsPanel from "@/components/RedactionsPanel";
import type { ScanResponse, AIAnalyzeOut, Neighbor, PersistedScan, EmailIn, HistoryItem } from "@/types/scan";

type Step = 0 | 1 | 2; // 0: Input, 1: Phase-1, 2: AI

export default function ScanPage() {
  const apiBase = process.env.NEXT_PUBLIC_API_URL;
  const envMissing = !apiBase;

  const [step, setStep] = React.useState<Step>(0);
  const [phase1, setPhase1] = React.useState<ScanResponse | null>(null);
  const [ai, setAI] = React.useState<AIAnalyzeOut | null>(null);
  const [phase1Error, setPhase1Error] = React.useState<string | null>(null);
  const [aiError, setAIError] = React.useState<string | null>(null);
  const [loadingPhase1, setLoadingPhase1] = React.useState(false);
  const [loadingAI, setLoadingAI] = React.useState(false);
  const [initialForm, setInitialForm] = React.useState<Partial<EmailIn>>({});
  const [resetSignal, setResetSignal] = React.useState<number>(0);
  const [csvQueue, setCsvQueue] = React.useState<EmailIn[] | null>(null);
  const [csvCountdown, setCsvCountdown] = React.useState<number>(0);
  const [csvTotals, setCsvTotals] = React.useState<{ types: Record<string, number>; count: number } | null>(null);

  const abortRefs = React.useRef<{ scan?: AbortController; ai?: AbortController }>({});
  const lastRawBody = React.useRef<string>("");

  const LS_KEY = "scan:last";
  const LS_HISTORY = "scan:history";
  const HISTORY_EVENT = "scan:history:updated";

  function getSenderDomain(indicators: unknown): string {
    try {
      if (!indicators || typeof indicators !== "object") return "";
      const obj = indicators as Record<string, unknown>;
      const val = obj["sender_domain"];
      return typeof val === "string" ? val : "";
    } catch {
      return "";
    }
  }

  function parseCsvToEmailIn(csv: string): EmailIn[] {
    const lines = csv.split(/\r?\n/).filter((l) => l.trim().length > 0);
    if (lines.length === 0) return [];
    const [headerLine, ...dataLines] = lines;
    const headers = headerLine.split(",").map((h) => h.trim().toLowerCase());
    const idx = (name: string) => headers.indexOf(name);
    const iSender = idx("sender");
    const iSenderEmail = idx("sender_email");
    const iReceiver = idx("receiver");
    const iSubject = idx("subject");
    const iBody = idx("body");
    const iUrl = idx("url");

    const rows: EmailIn[] = [];
    for (const line of dataLines) {
      const cols = splitCsvLine(line, headers.length);
      const sender = String((iSenderEmail >= 0 ? cols[iSenderEmail] : cols[iSender]) ?? "").trim();
      const subject = String(cols[iSubject] ?? "").trim();
      const body = String(cols[iBody] ?? "").trim();
      if (!sender || !subject || !body) continue;
      const receiver = String(cols[iReceiver] ?? "").trim() || undefined;
      const urlVal = String(cols[iUrl] ?? "").trim();
      const url: 0 | 1 = urlVal === "1" || /(?:https?:\/\/|www\.)/i.test(body) ? 1 : 0;
      rows.push({ sender, receiver, subject, body, url });
    }
    return rows;
  }

  function splitCsvLine(line: string, expectedCols: number): string[] {
    const result: string[] = [];
    let current = "";
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (ch === '"') {
        if (inQuotes && line[i + 1] === '"') {
          current += '"';
          i++;
        } else {
          inQuotes = !inQuotes;
        }
      } else if (ch === "," && !inQuotes) {
        result.push(current);
        current = "";
      } else {
        current += ch;
      }
    }
    result.push(current);
    while (result.length < expectedCols) result.push("");
    return result;
  }

  function appendHistory(persisted: PersistedScan) {
    try {
      const id = `${persisted.savedAt}-${Math.random().toString(36).slice(2, 8)}`;
      const entry: HistoryItem = { id, ...persisted };
      const raw = localStorage.getItem(LS_HISTORY);
      const arr: HistoryItem[] = raw ? (JSON.parse(raw) as HistoryItem[]) : [];
      arr.unshift(entry);
      localStorage.setItem(LS_HISTORY, JSON.stringify(arr.slice(0, 500)));
      window.dispatchEvent(new CustomEvent(HISTORY_EVENT));
    } catch {}
  }

  function parseErrorResponse(status: number, detail: unknown): string {
    if (typeof detail === "string") return `HTTP ${status}: ${detail}`;
    if (detail && typeof detail === "object") {
      const obj = detail as Record<string, unknown>;
      const candidate = (obj["error"] ?? obj["detail"] ?? obj["message"]);
      if (typeof candidate === "string") {
        return `HTTP ${status}: ${candidate}`;
      }
      return `HTTP ${status}: Request failed`;
    }
    return `HTTP ${status}: Request failed`;
  }

  async function fetchJson<T>(url: string, init: RequestInit & { signal?: AbortSignal }): Promise<T> {
    const res = await fetch(url, init);
    if (!res.ok) {
      let detail: unknown = null;
      try {
        detail = await res.json();
      } catch {
        try {
          detail = await res.text();
        } catch {
          detail = null;
        }
      }
      throw new Error(parseErrorResponse(res.status, detail));
    }
    return (await res.json()) as T;
  }

  async function analyzeOnce(values: EmailIn): Promise<ScanResponse | undefined> {
    if (envMissing) return;

    // Abort any in-flight requests
    abortRefs.current.scan?.abort();
    abortRefs.current.ai?.abort();

    setStep(1);
    setPhase1(null);
    setAI(null);
    setPhase1Error(null);
    setAIError(null);
    setLoadingPhase1(true);
    setLoadingAI(true);
    lastRawBody.current = values.body;

    const scanController = new AbortController();
    const aiController = new AbortController();
    abortRefs.current.scan = scanController;
    abortRefs.current.ai = aiController;

    const payload = JSON.stringify({
      sender: values.sender,
      receiver: values.receiver,
      subject: values.subject,
      body: values.body,
      url: values.url,
    });

    // Fire both requests concurrently for faster CSV processing
    const scanPromise = fetchJson<ScanResponse>(`${apiBase}/scan`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: payload,
      signal: scanController.signal,
    })
      .then((data) => {
        setPhase1(data);
        return data;
      })
      .catch((err) => {
        if (!scanController.signal.aborted) setPhase1Error(String(err));
        return undefined;
      })
      .finally(() => {
        if (!scanController.signal.aborted) setLoadingPhase1(false);
      });

    const aiPromise = fetchJson<AIAnalyzeOut>(`${apiBase}/ai/analyze`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: payload,
      signal: aiController.signal,
    })
      .then((data) => {
        setAI(data);
        if (data?.phase1) setPhase1(data.phase1);
        return data;
      })
      .catch((err) => {
        if (!aiController.signal.aborted) setAIError(String(err));
        return undefined;
      })
      .finally(() => {
        if (!aiController.signal.aborted) setLoadingAI(false);
      });

    setStep(2);
    const [scanData, aiData] = await Promise.all([scanPromise, aiPromise]);

    if (aiData?.phase1) {
      try {
        const domain = getSenderDomain(aiData.phase1?.indicators);
        const neighborsTop3: Neighbor[] = Array.isArray(aiData.neighbors) ? aiData.neighbors.slice(0, 3) : [];
        const persisted: PersistedScan = {
          input: values,
          domain,
          phase1: aiData.phase1,
          neighborsTop3,
          ai: { ai_verdict: aiData.ai_verdict, ai_label: aiData.ai_label, ai_score: aiData.ai_score, ai_reasons: aiData.ai_reasons },
          savedAt: Date.now(),
        };
        localStorage.setItem(LS_KEY, JSON.stringify(persisted));
        appendHistory(persisted);
      } catch {}
    }

    const effectivePhase1: ScanResponse | undefined = aiData?.phase1 ?? scanData;
    return effectivePhase1;
  }

  function handleSubmit(values: { sender: string; receiver?: string; subject: string; body: string; url: 0 | 1 }) {
    analyzeOnce(values);
  }

  function handleReset() {
    try {
      localStorage.removeItem(LS_KEY);
    } catch {}
    setPhase1(null);
    setAI(null);
    setPhase1Error(null);
    setAIError(null);
    setStep(0);
    setInitialForm({});
    lastRawBody.current = "";
    setResetSignal((n) => n + 1);
    setCsvTotals(null);
  }

  React.useEffect(() => {
    return () => {
      abortRefs.current.scan?.abort();
      abortRefs.current.ai?.abort();
    };
  }, []);

  // Hydrate from previous session
  React.useEffect(() => {
    try {
      const raw = localStorage.getItem(LS_KEY);
      if (!raw) return;
      const saved = JSON.parse(raw) as PersistedScan;
      if (!saved || !saved.phase1) return;
      setPhase1(saved.phase1);
      setAI({
        phase1: saved.phase1,
        neighbors: saved.neighborsTop3,
        phish_neighbors: [],
        ai_verdict: saved.ai.ai_verdict,
        ai_label: saved.ai.ai_label,
        ai_score: saved.ai.ai_score,
        ai_reasons: saved.ai.ai_reasons,
      });
      setInitialForm(saved.input);
      setStep(2);
      lastRawBody.current = saved.input?.body ?? "";
    } catch {}
  }, []);

  // CSV processing: handle a single row per effect run to avoid stale closures.
  React.useEffect(() => {
    if (!csvQueue || csvQueue.length === 0) return;

    let cancelled = false;

    const runOne = async () => {
      const next = csvQueue[0];
      // Reflect current row in the form
      setInitialForm(next);
      const phase1Result = await analyzeOnce(next);
      if (phase1Result?.redactions) {
        const red = phase1Result.redactions;
        setCsvTotals((prev) => {
          const mergedTypes: Record<string, number> = { ...(prev?.types ?? {}) };
          for (const [k, v] of Object.entries(red.types || {})) {
            mergedTypes[k] = (mergedTypes[k] ?? 0) + (typeof v === "number" ? v : 0);
          }
          const totalCount = (prev?.count ?? 0) + (typeof red.count === "number" ? red.count : 0);
          return { types: mergedTypes, count: totalCount };
        });
      }
      // Reset form between rows for clarity
      setResetSignal((n) => n + 1);
      // 8-second countdown before proceeding to the next row (was 5s)
      for (let s = 8; s > 0 && !cancelled; s--) {
        setCsvCountdown(s);
        await new Promise((r) => setTimeout(r, 1000));
      }
      setCsvCountdown(0);
      if (!cancelled) {
        setCsvQueue((q) => (q && q.length > 1 ? q.slice(1) : null));
      }
    };

    runOne();
    return () => {
      cancelled = true;
    };
  }, [csvQueue]);

  return (
    <main className="min-h-screen bg-gradient-to-b from-white to-slate-50 dark:from-slate-900 dark:to-slate-950 p-8">
      <div className="mx-auto max-w-6xl space-y-6">
        <div className="flex flex-col items-start justify-between gap-4 md:flex-row md:items-center">
      
          <ScanStepper step={step} loadingPhase1={loadingPhase1} loadingAI={loadingAI} />
        </div>

        {envMissing && (
          <div role="alert" className="rounded-md border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900">
            NEXT_PUBLIC_API_URL is not configured. Set it to your FastAPI base URL.
          </div>
        )}

        <div className="grid gap-6 lg:grid-cols-2">
          <section className="rounded-2xl border bg-white/60 dark:bg-slate-900/40 backdrop-blur p-6 shadow-sm">
            <h1 className="text-xl font-semibold mb-4">Email Scan</h1>
            <ScanForm
              onSubmit={handleSubmit}
              loading={loadingPhase1 || loadingAI}
              initial={initialForm}
              onReset={handleReset}
              resetSignal={resetSignal}
              onUploadCsv={async (file) => {
                const text = await file.text();
                // Expect CSV with headers: sender,receiver,subject,body,url(optional)
                const rows = parseCsvToEmailIn(text);
                if (rows.length > 0) {
                  setCsvQueue(rows);
                  // Show first row in the form immediately
                  setInitialForm(rows[0]);
                  // Reset running PII totals for this CSV session
                  setCsvTotals({ types: {}, count: 0 });
                }
              }}
            />
            {csvQueue && (
              <div className="mt-3 text-sm text-slate-600">CSV processing: {csvQueue.length} remaining{csvCountdown ? ` • next in ${csvCountdown}s` : ""}</div>
            )}
          </section>

          <div className="space-y-6">
            <Phase1Card data={phase1} loading={loadingPhase1} error={phase1Error} />
            <AIInsightsCard data={ai ? { ai_verdict: ai.ai_verdict, ai_reasons: ai.ai_reasons } : null} loading={loadingAI} error={aiError} />
          </div>

          <NeighborsList neighbors={ai?.neighbors ?? null} loading={loadingAI && !ai} error={aiError} className="lg:col-span-2" />

          <RedactionsPanel
            redactions={csvTotals ?? (ai?.phase1 ?? phase1 ?? null)?.redactions ?? null}
            redactedBody={(ai?.phase1 ?? phase1 ?? null)?.redacted_body ?? null}
            rawBody={lastRawBody.current}
            loading={loadingPhase1 && !phase1}
            error={phase1Error}
            className="lg:col-span-2"
          />
        </div>
      </div>
    </main>
  );
}

