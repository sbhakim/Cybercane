"use client";

import ChallengeShell from "./components/ChallengeShell";
import EmailChallenge from "./components/EmailChallenge";
import PhoneChallenge from "./components/PhoneChallenge";
import UrlChallenge from "./components/UrlChallenge";
import type { ChallengeResult } from "./lib/flags";

export default function ElderlyTrainingPage() {
  return (
    <main className="min-h-screen bg-gradient-to-b from-white to-slate-50 dark:from-slate-900 dark:to-slate-950">
      <div className="mx-auto max-w-5xl px-4 py-8">
        <header className="mb-6">
          <h1 className="text-2xl md:text-3xl font-bold tracking-tight">Elderly Training CTF</h1>
          <p className="text-slate-600 dark:text-slate-300 mt-1">Learn to spot scams in minutes.</p>
        </header>

        <ChallengeShell>
          {({ results, onSolved, registerRef }) => {
            // Helper to pass last known selection state to each challenge
            const getResult = (id: string): ChallengeResult | undefined => results.find(r => r.id === id);
            return (
              <div className="space-y-6 pb-24">
                <EmailChallenge result={getResult("email")} onSolved={onSolved} registerRef={registerRef} />
                <PhoneChallenge result={getResult("phone")} onSolved={onSolved} registerRef={registerRef} />
                <UrlChallenge result={getResult("url")} onSolved={onSolved} registerRef={registerRef} />
              </div>
            );
          }}
        </ChallengeShell>
      </div>
    </main>
  );
}


