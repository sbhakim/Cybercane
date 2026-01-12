"use client";

import ChallengeShell from "./components/ChallengeShell";
import EmailChallenge from "./components/EmailChallenge";
import PhoneChallenge from "./components/PhoneChallenge";
import UrlChallenge from "./components/UrlChallenge";

export default function MiniGameSection() {
  return (
    <section className="rounded-2xl border bg-white/60 dark:bg-slate-900/40 backdrop-blur p-6 shadow-sm">
      <h2 className="text-lg font-semibold mb-4">Elderly Training Mini‑Game</h2>
      <p className="text-sm text-slate-600 dark:text-slate-300 mb-4">
        Solve all three challenges to unlock the final flag.
      </p>
      <ChallengeShell>
        {({ results, onSolved, registerRef }) => {
          const get = (id: string) => results.find(r => r.id === id);
          return (
            <div className="grid gap-6">
              <div>
                <EmailChallenge result={get("email")} onSolved={onSolved} registerRef={registerRef} />
              </div>
              <div>
                <PhoneChallenge result={get("phone")} onSolved={onSolved} registerRef={registerRef} />
              </div>
              <div>
                <UrlChallenge result={get("url")} onSolved={onSolved} registerRef={registerRef} />
              </div>
            </div>
          );
        }}
      </ChallengeShell>
    </section>
  );
}


