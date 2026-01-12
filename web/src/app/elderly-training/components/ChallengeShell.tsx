"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { ChallengeResult } from "../lib/flags";
import { pseudoHash, verifyServerFlag } from "../lib/flags";

type OnSolvedArgs = { id: string; points: number; payload: string };

const STORAGE_KEY = "elderly-ctf-progress";

function loadProgress(): ChallengeResult[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    return raw ? (JSON.parse(raw) as ChallengeResult[]) : [];
  } catch {
    return [];
  }
}

function saveProgress(results: ChallengeResult[]) {
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(results));
  } catch {
    // ignore
  }
}

export default function ChallengeShell({
  children,
}: {
  children: (args: {
    results: ChallengeResult[];
    onSolved: (args: OnSolvedArgs) => Promise<void>;
    registerRef: (id: string, el: HTMLDivElement | null) => void;
  }) => React.ReactNode;
}) {
  const [results, setResults] = useState<ChallengeResult[]>([]);
  const [verifying, setVerifying] = useState<string | null>(null);
  const refs = useRef<Record<string, HTMLDivElement | null>>({});

  useEffect(() => {
    setResults(loadProgress());
  }, []);

  useEffect(() => {
    if (results.length) saveProgress(results);
  }, [results]);

  const solvedCount = useMemo(() => results.filter(r => r.solved).length, [results]);
  const totalPoints = useMemo(() => results.reduce((sum, r) => sum + (r.solved ? r.points : 0), 0), [results]);
  const allSolved = solvedCount === 3;

  const finalFlag = useMemo(() => {
    if (!allSolved) return null;
    const flags = results
      .filter(r => r.solved && r.serverFlag)
      .map(r => r.serverFlag)
      .join("|");
    if (!flags) return null;
    const token = pseudoHash(flags);
    return `CYBERCANE-FINAL{${token}}`;
  }, [results, allSolved]);

  function registerRef(id: string, el: HTMLDivElement | null) {
    refs.current[id] = el;
  }

  async function onSolved({ id, points, payload }: OnSolvedArgs) {
    // Avoid double-credit
    const existing = results.find(r => r.id === id && r.solved);
    if (existing) return;
    try {
      setVerifying(id);
      const flag = await verifyServerFlag(id, payload);
      const updated: ChallengeResult = {
        id,
        solved: true,
        points,
        selections: { indicators: [] },
        solvedAt: new Date().toISOString(),
        serverFlag: flag,
      };
      setResults(prev => {
        const others = prev.filter(r => r.id !== id);
        return [...others, updated].sort((a, b) => a.id.localeCompare(b.id));
      });
    } finally {
      setVerifying(null);
    }
  }

  return (
    <div className="space-y-6">
      {/* Completion banner */}
      {allSolved && finalFlag && (
        <div className="rounded-2xl border bg-emerald-50 dark:bg-emerald-900/20 border-emerald-200 dark:border-emerald-800 p-4">
          <h2 className="text-lg font-semibold text-emerald-800 dark:text-emerald-300">You finished!</h2>
          <p className="text-sm text-emerald-900/80 dark:text-emerald-300/80 mt-1">
            Final flag: <span className="font-mono select-none">{finalFlag}</span>
          </p>
          <ul className="list-disc pl-5 mt-3 text-sm text-slate-700 dark:text-slate-300">
            <li>Verify sender or caller using trusted channels.</li>
            <li>Never pay with gift cards or wire transfers.</li>
            <li>Check URLs and padlocks; when unsure, call your provider.</li>
          </ul>
        </div>
      )}

      {children({ results, onSolved, registerRef })}

      {/* Sticky progress footer */}
      <div className="fixed inset-x-0 bottom-0 z-20">
        <div className="mx-auto max-w-5xl px-4 pb-4">
          <div className="rounded-xl border bg-white/80 dark:bg-slate-900/80 backdrop-blur px-4 py-3 shadow-sm flex items-center justify-between">
            <div className="text-sm">
              <span className="font-medium">Solved {solvedCount}/3</span>
              <span className="mx-2 text-slate-400">·</span>
              <span>{totalPoints} pts</span>
              {verifying && <span className="ml-2 text-slate-500">Verifying...</span>}
            </div>
            <div className="flex gap-2 text-xs">
              {["email","phone","url"].map((id, idx) => {
                const r = results.find(x => x.id === id);
                const solved = r?.solved;
                return (
                  <button
                    key={id}
                    type="button"
                    onClick={() => refs.current[id]?.scrollIntoView({ behavior: "smooth", block: "start" })}
                    className={
                      "rounded-full px-3 py-1 border focus:outline-none focus:ring-2 focus:ring-indigo-400 " +
                      (solved
                        ? "bg-emerald-50 border-emerald-200 text-emerald-800 dark:bg-emerald-900/30 dark:border-emerald-800 dark:text-emerald-300"
                        : "bg-white dark:bg-slate-800 border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300")
                    }
                    aria-current={idx === 0 ? undefined : undefined}
                  >
                    {idx + 1}
                  </button>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}


