"""
E1-confirm: out-of-sample confirmation of the CC x LLM ECDF fusion.

Protocol and success criteria were fixed before the run (E1-confirm, preregistration table in the paper).
The fusion design is fixed by E1; here it is applied unchanged to the CEAS and
Ling benign sources. CPU only; uses cached embeddings and B12 responses.

Usage:
  CUDA_VISIBLE_DEVICES="" PYTHONPATH=api python -m app.evaluation.e1_confirm
"""

import argparse
import json
import subprocess
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

from app.evaluation.e1_e2_gap_closing import ecdf, eval_scores
from app.evaluation.llm_zero_shot import CACHE_FILE as B12_CACHE
from app.evaluation.pilot_c1_shift import WS, fit_scorers
from app.evaluation.r2_benign_shift import benign, dataphish, decontaminate, nazario
from app.evaluation.r5_style_shift import concat

PAIRS = ("ceas", "ling")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, nargs="+", default=[42, 1, 2, 3, 4])
    args = ap.parse_args()
    out = WS / "reports_v2" / f"e1_confirm_{datetime.now():%Y%m%d_%H%M%S}"
    out.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(0)
    b12 = pd.DataFrame([json.loads(l) for l in B12_CACHE.read_text().splitlines()])
    b12 = b12[b12.status == "ok"].drop_duplicates("row_uid", keep="last").set_index("row_uid").prob

    rows = []
    for seed in args.seeds:
        dp_test = dataphish("test", seed)
        for pair in PAIRS:
            src_tr = concat(nazario("train", seed), benign(pair, "train", seed))
            src_va = concat(nazario("val", seed), benign(pair, "val", seed))
            tgt, _ = decontaminate(dp_test, src_tr)
            score = fit_scorers(src_tr)
            ccv, cct = score(src_va)["CC_full"], score(tgt)["CC_full"]
            lv = b12.reindex(src_va.row_uid).values.astype(float)
            lt = b12.reindex(tgt.row_uid).values.astype(float)
            assert not np.isnan(lv).any() and not np.isnan(lt).any(), f"missing B12 scores ({pair}, seed {seed})"
            neg = src_va.y.values == 0
            f_cc, f_llm = ecdf(ccv[neg]), ecdf(lv[neg])
            rows += eval_scores("E1-confirm", pair, seed,
                                {"CC_full": ccv, "B12_llm": lv, "E1_fusion": 0.5 * (f_cc(ccv) + f_llm(lv))},
                                {"CC_full": cct, "B12_llm": lt, "E1_fusion": 0.5 * (f_cc(cct) + f_llm(lt))},
                                src_va, tgt, rng)
            print(f"seed {seed} {pair}: done", flush=True)

    res = pd.DataFrame(rows)
    res.to_csv(out / "results.csv", index=False)
    g = res[(res.rule == "budget") & (res.budget == 0.01)]
    verdict = []
    for pair, h in g.groupby("pair"):
        m = h.groupby("method")[["test_fpr", "recall"]].mean()
        verdict.append(dict(pair=pair,
                            cc_fpr=m.loc["CC_full", "test_fpr"], cc_rec=m.loc["CC_full", "recall"],
                            fu_fpr=m.loc["E1_fusion", "test_fpr"], fu_rec=m.loc["E1_fusion", "recall"],
                            llm_fpr=m.loc["B12_llm", "test_fpr"], llm_rec=m.loc["B12_llm", "recall"],
                            confirms=bool(m.loc["E1_fusion", "recall"] >= m.loc["CC_full", "recall"] + 0.03
                                          and m.loc["E1_fusion", "test_fpr"] <= m.loc["CC_full", "test_fpr"])))
    crit = dict(pairs=verdict, confirmed=all(v["confirms"] for v in verdict))
    commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                            cwd=Path(__file__).resolve().parents[3]).stdout.strip()
    (out / "run_manifest.json").write_text(json.dumps(dict(
        purpose="E1-confirm preregistered out-of-sample fusion test", seeds=args.seeds, pairs=PAIRS,
        commit=commit, criterion=crit), indent=2, default=float))
    print("CRITERION", json.dumps(crit, default=float))
    print("wrote", out)


if __name__ == "__main__":
    main()
