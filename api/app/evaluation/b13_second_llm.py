"""
B13: second zero-shot LLM (Llama 3.3 70B) on the F1 matched-FPR frontier.

Protocol and success criteria were fixed before the run (B13, preregistration table in the paper).
Joins the B13 cache (same prompt, rows, and text as B12) onto the per-example
scores saved by F1, so CyberCane and B12 scores are exactly those of F1.
Failed calls are scored as 50 and counted, as in B12. CPU only; no provider calls.

Usage:
  PYTHONPATH=api python -m app.evaluation.b13_second_llm
"""

import json
import subprocess
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

from app.evaluation.frontier_f1 import FPR_LEVELS, recall_at_fpr
from app.evaluation.pilot_c1_shift import WS

CACHE = WS / "cache_v2" / "llm_meta-llama_llama-3.3-70b-instruct_b12_v1.jsonl"


def main():
    f1_dir = sorted((WS / "reports_v2").glob("f1_frontier_*"))[-1]
    sc = pd.read_csv(f1_dir / "scores.csv")
    lines = [json.loads(l) for l in CACHE.read_text().splitlines()]
    cache = pd.DataFrame(lines).drop_duplicates("row_uid", keep="last").set_index("row_uid")
    ok = cache.status == "ok"
    sc["B13_llama"] = cache.prob.where(ok).reindex(sc.row_uid).values.astype(float)
    n_fail = int(np.isnan(sc.drop_duplicates("row_uid").B13_llama).sum())
    sc["B13_llama"] = sc.B13_llama.fillna(50.0)
    out = WS / "reports_v2" / f"b13_second_llm_{datetime.now():%Y%m%d_%H%M%S}"
    out.mkdir(parents=True, exist_ok=True)

    rows = []
    for (seed, pair), g in sc.groupby(["seed", "pair"]):
        y = g.y.values
        for m in ("CC_full", "B12_llm", "B13_llama"):
            s = g[m].values
            rows.append(dict(seed=seed, pair=pair, method=m, auroc=roc_auc_score(y, s),
                             pauc2=roc_auc_score(y, s, max_fpr=0.02),
                             default_fpr=float((s[y == 0] >= 50).mean()) if m != "CC_full" else np.nan,
                             default_recall=float((s[y == 1] >= 50).mean()) if m != "CC_full" else np.nan,
                             **{f"recall_at_{lv}": recall_at_fpr(y, s, lv) for lv in FPR_LEVELS}))
    res = pd.DataFrame(rows)
    res.to_csv(out / "results.csv", index=False)

    l1, l2 = {}, {}
    for pair, h in res.groupby("pair"):
        piv = h.pivot_table(index="seed", columns="method", values="recall_at_0.01")
        l1[pair] = int((piv.CC_full > piv.B13_llama).sum())
        mm = h.groupby("method")["recall_at_0.1"].mean()
        l2[pair] = bool(mm["B13_llama"] > mm["CC_full"])
    verdict = dict(L1_seeds_cc_above_llama_at_1pct=l1, L1=sum(v >= 4 for v in l1.values()) >= 2,
                   L2_llama_above_cc_at_10pct=l2, L2=sum(l2.values()) >= 2, failed_calls_scored_50=n_fail,
                   total_cost_usd=float(sum(r.get("cost", 0.0) for r in lines)),
                   providers=pd.Series([r.get("provider") for r in lines]).value_counts().to_dict())
    commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                            cwd=Path(__file__).resolve().parents[3]).stdout.strip()
    (out / "run_manifest.json").write_text(json.dumps(dict(
        purpose="B13 preregistered second zero-shot LLM on the F1 frontier", f1_scores=str(f1_dir),
        model="meta-llama/llama-3.3-70b-instruct", provider_pin="novita/bf16", commit=commit,
        criterion=verdict), indent=2, default=str))
    cols = ["recall_at_0.005", "recall_at_0.01", "recall_at_0.02", "recall_at_0.05", "recall_at_0.1", "pauc2"]
    print((res.groupby(["pair", "method"])[cols].mean()).round(3).to_string())
    print("CRITERION", json.dumps(verdict, default=str))
    print("wrote", out)


if __name__ == "__main__":
    main()
