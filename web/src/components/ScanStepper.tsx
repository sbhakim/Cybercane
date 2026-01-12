"use client";

type Step = 0 | 1 | 2; // 0: Input, 1: Phase-1, 2: AI

type ScanStepperProps = {
  step: Step;
  loadingPhase1?: boolean;
  loadingAI?: boolean;
  className?: string;
};

function StepDot({ active, done }: { active: boolean; done: boolean }) {
  const base = "h-2.5 w-2.5 rounded-full";
  const cls = done
    ? "bg-emerald-500"
    : active
    ? "bg-blue-600 animate-pulse"
    : "bg-slate-300";
  return <span className={`${base} ${cls}`} aria-hidden />;
}

export default function ScanStepper({ step, loadingPhase1 = false, loadingAI = false, className = "" }: ScanStepperProps) {
  const steps = ["Input", "Phase‑1", "AI"] as const;
  return (
    <div className={`flex items-center gap-3 ${className}`} role="progressbar" aria-valuemin={0} aria-valuemax={2} aria-valuenow={step}>
      {steps.map((label, idx) => {
        const active = step === idx;
        const done = step > idx;
        const loading = (idx === 1 && loadingPhase1) || (idx === 2 && loadingAI);
        return (
          <div key={label} className="flex items-center gap-2">
            <StepDot active={active} done={done} />
            <span className={`text-sm ${done ? "text-slate-900" : active ? "text-blue-700" : "text-slate-500"}`}>
              {label}
              {loading && <span className="ml-1 text-xs text-slate-400">(loading)</span>}
            </span>
            {idx < steps.length - 1 && <span className="mx-1 h-px w-8 bg-slate-200" aria-hidden />}
          </div>
        );
      })}
    </div>
  );
}


