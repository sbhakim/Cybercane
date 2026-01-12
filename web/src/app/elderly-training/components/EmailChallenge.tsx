"use client";

import { useEffect, useId, useMemo, useRef, useState } from "react";
import type { ChallengeResult, Indicator, Verdict } from "../lib/flags";

const ID = "email";
const POINTS = 100;
const CORRECT_VERDICT: Verdict = "phish";
const ALL_INDICATORS: { key: Indicator; label: string; correct: boolean; help?: string }[] = [
  { key: "typo", label: "Typosquatted domain walgrens-support.com", correct: true, help: "Brand misspelling tricks users." },
  { key: "returnpath", label: "Return-Path mismatch vs From", correct: true, help: "Bounce address differs from visible From." },
  { key: "dkimnone", label: "DKIM missing dkim=none", correct: true, help: "Unsigned email is suspicious." },
  { key: "dmarcfail", label: "DMARC failed dmarc=fail", correct: true, help: "Policy check failed." },
  { key: "urgent", label: "Urgent lure / payment bait", correct: true, help: "Pressure tactics demand quick payment." },
  { key: "tone", label: "Respectful tone", correct: false },
];

const PAYLOAD = "phish|typo,returnpath,dkimnone,dmarcfail,urgent";

export default function EmailChallenge({
  result,
  onSolved,
  registerRef,
}: {
  result?: ChallengeResult;
  onSolved: (args: { id: string; points: number; payload: string }) => void;
  registerRef: (id: string, el: HTMLDivElement | null) => void;
}) {
  const formId = useId();
  const [verdict, setVerdict] = useState<Verdict | undefined>(result?.selections?.verdict);
  const [checks, setChecks] = useState<Record<string, boolean>>({});
  const [feedback, setFeedback] = useState<string>("");
  const sectionRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    registerRef(ID, sectionRef.current);
  }, [registerRef]);

  useEffect(() => {
    if (result?.selections?.indicators?.length) {
      const map: Record<string, boolean> = {};
      for (const k of result.selections.indicators) map[k] = true;
      setChecks(map);
    }
    if (result?.selections?.verdict) setVerdict(result.selections.verdict);
  }, [result]);

  const allCorrectKeys = useMemo(() => ALL_INDICATORS.filter(i => i.correct).map(i => i.key), []);

  function handleCheck(key: string) {
    setChecks(prev => ({ ...prev, [key]: !prev[key] }));
  }

  function resetFeedbackSoon(msg: string) {
    setFeedback(msg);
    window.setTimeout(() => setFeedback(""), 3000);
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (result?.solved) return;
    const selected = Object.entries(checks).filter(([, v]) => v).map(([k]) => k);
    const exactMatch =
      verdict === CORRECT_VERDICT &&
      selected.length === allCorrectKeys.length &&
      allCorrectKeys.every(k => selected.includes(k));
    if (!verdict) return resetFeedbackSoon("Choose a verdict.");
    if (!exactMatch) return resetFeedbackSoon("Not quite. Review headers/indicators and try again.");
    onSolved({ id: ID, points: POINTS, payload: PAYLOAD });
  }

  return (
    <div ref={sectionRef} className="rounded-2xl border bg-white shadow-sm dark:bg-slate-900/60 dark:border-slate-800 p-6">
      <h3 className="text-lg font-semibold">Email Phish Investigator</h3>
      <p className="text-sm text-slate-600 dark:text-slate-300 mt-1">Review the headers and body, then decide.</p>

      <div className="mt-4 grid gap-3 text-sm">
        <div className="rounded-md border p-3 bg-slate-50 dark:bg-slate-800/50">
          <pre className="whitespace-pre-wrap break-words text-xs leading-relaxed">
{`From: "Walgrens Pharmacy" <alerts@walgrens-support.com>
Return-Path: bounce@mail.walgrens-support.com
Authentication-Results: spf=fail; dkim=none; dmarc=fail
Body: Refill ready — pay $1 to release: http://walgrens-support.com/refill`}
          </pre>
        </div>
      </div>

      <form onSubmit={handleSubmit} aria-describedby={`${formId}-feedback`} className="mt-4 space-y-4">
        <fieldset>
          <legend className="text-sm font-medium">Verdict</legend>
          <div className="mt-2 flex gap-2">
            <button
              type="button"
              onClick={() => setVerdict("phish")}
              className={
                "min-h-11 rounded-lg px-4 py-2 border focus:outline-none focus:ring-2 focus:ring-indigo-400 " +
                (verdict === "phish"
                  ? "bg-indigo-600 text-white border-indigo-600"
                  : "bg-white dark:bg-slate-800 border-slate-200 dark:border-slate-700")
              }
              aria-pressed={verdict === "phish"}
            >
              Phish
            </button>
            <button
              type="button"
              onClick={() => setVerdict("benign")}
              className={
                "min-h-11 rounded-lg px-4 py-2 border focus:outline-none focus:ring-2 focus:ring-indigo-400 " +
                (verdict === "benign"
                  ? "bg-indigo-600 text-white border-indigo-600"
                  : "bg-white dark:bg-slate-800 border-slate-200 dark:border-slate-700")
              }
              aria-pressed={verdict === "benign"}
            >
              Benign
            </button>
          </div>
        </fieldset>

        <fieldset>
          <legend className="text-sm font-medium">Indicators (select all that apply)</legend>
          <ul className="mt-2 grid gap-2">
            {ALL_INDICATORS.map((it, idx) => (
              <li key={it.key} className="flex items-start gap-3">
                <input
                  id={`${formId}-cb-${idx}`}
                  type="checkbox"
                  className="mt-1 h-4 w-4 rounded border-slate-300 text-indigo-600 focus:ring-indigo-400"
                  checked={!!checks[it.key]}
                  onChange={() => handleCheck(it.key)}
                />
                <label htmlFor={`${formId}-cb-${idx}`} className="text-sm select-text">
                  {it.label}
                </label>
                {it.help && (
                  <span className="ml-auto text-xs text-slate-500" aria-label="help" title={it.help}>?</span>
                )}
              </li>
            ))}
          </ul>
        </fieldset>

        <div className="flex items-center gap-3">
          <button
            type="submit"
            disabled={!!result?.solved}
            className={
              "min-h-11 rounded-lg px-4 py-2 border focus:outline-none focus:ring-2 focus:ring-indigo-400 " +
              (result?.solved
                ? "bg-slate-200 dark:bg-slate-700 text-slate-500 cursor-not-allowed"
                : "bg-indigo-600 text-white border-indigo-600 hover:bg-indigo-700")
            }
          >
            {result?.solved ? "Solved" : "Submit"}
          </button>
          {result?.solved && result.serverFlag && (
            <span className="select-none font-mono text-xs rounded border px-2 py-0.5 bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-900/30 dark:text-emerald-300 dark:border-emerald-700">
              {result.serverFlag}
            </span>
          )}
        </div>

        <p id={`${formId}-feedback`} aria-live="polite" className="text-sm text-slate-600 dark:text-slate-300">
          {feedback}
        </p>
      </form>
    </div>
  );
}


