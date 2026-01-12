type Health = { status?: string; db?: boolean };

export default async function HealthPage() {
  const api =
    (process.env.NEXT_RUNTIME === "nodejs"
      ? process.env.INTERNAL_API_URL
      : process.env.NEXT_PUBLIC_API_URL) || "http://localhost:8000";

  let health: Health = {};
  try {
    const res = await fetch(`${api}/health`, { cache: "no-store" });
    health = await res.json();
  } catch {
    health = { status: "down", db: false };
  }

  const apiOk = health.status === "ok";
  const dbOk = Boolean(health.db);

  const badge = (ok: boolean) =>
    `inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium ${
      ok
        ? "bg-green-100 text-green-700 border-green-200"
        : "bg-red-100 text-red-700 border-red-200"
    }`;

  return (
    <main className="min-h-screen bg-gradient-to-b from-white to-slate-50 dark:from-slate-900 dark:to-slate-950 p-8">
      <div className="mx-auto max-w-5xl space-y-8">
        <h1 className="text-2xl font-bold">System Health</h1>
        <section className="rounded-2xl border bg-white/60 dark:bg-slate-900/40 backdrop-blur p-6 shadow-sm">
          <h2 className="text-lg font-semibold mb-4">Health Checks</h2>
          <div className="flex flex-wrap items-center gap-3">
            <span className={badge(apiOk)}>API: {apiOk ? "ok" : "down"}</span>
            <span className={badge(dbOk)}>DB: {dbOk ? "ok" : "down"}</span>
            <code className="rounded-md bg-slate-100 dark:bg-slate-800 px-2 py-1 text-xs">{api}/health</code>
          </div>
        </section>
      </div>
    </main>
  );
}
