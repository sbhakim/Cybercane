"""
V1: retrieval-gated LLM verification cascade.

Protocol and success criteria were fixed before the run (V1, preregistration table in the paper).
alert = (prefilter score >= review threshold at 8b on source-validation
legitimate mail) AND (zero-shot LLM probability >= 50). The LLM cut-off is
fixed, never tuned. LLM scores come from the B12 cache; no provider calls.
Forward benign shift (SpamAssassin / CEAS / Ling-Spam -> decontaminated
DataPhish 2025 test), 5 seeds. CPU only.

Usage:
  CUDA_VISIBLE_DEVICES="" PYTHONPATH=api python -m app.evaluation.v1_cascade             # V1 (gpt-oss-120b, B12 cache)
  CUDA_VISIBLE_DEVICES="" PYTHONPATH=api python -m app.evaluation.v1_cascade --llm b13   # S1 (Llama 3.3 70B, B13 cache)

S1 (preregistered October 4, 2026) reuses this design unchanged with the B13 scores, and adds a descriptive
gate sweep for CC (2b, 4b, 8b, 16b); the 8b gate stays the reported operating point.
"""

import argparse
import json
import subprocess
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

from app.evaluation.llm_zero_shot import CACHE_FILE as B12_CACHE
from app.evaluation.b13_second_llm import CACHE as B13_CACHE
from app.evaluation.pilot_c1_shift import BUDGETS, WS
from app.evaluation.r2_benign_shift import BENIGN, all_scores, benign, dataphish, decontaminate, nazario
from app.evaluation.r5_style_shift import concat
from app.evaluation.replicate_c1 import thresholds

PREFILTERS = ("CC_full", "B3_tfidf_lr", "B9_emb_lr", "B10_knn_2class")
LLM_CUT = 50


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, nargs="+", default=[42, 1, 2, 3, 4])
    ap.add_argument("--llm", choices=["b12", "b13"], default="b12")
    args = ap.parse_args()
    tag = "v1_cascade" if args.llm == "b12" else "s1_gate_llama"
    out = WS / "reports_v2" / f"{tag}_{datetime.now():%Y%m%d_%H%M%S}"
    out.mkdir(parents=True, exist_ok=True)

    cache = B12_CACHE if args.llm == "b12" else B13_CACHE
    b12 = pd.DataFrame([json.loads(l) for l in cache.read_text().splitlines()])
    b12 = b12[b12.status == "ok"].drop_duplicates("row_uid", keep="last").set_index("row_uid").prob

    rows = []
    for seed in args.seeds:
        dp_test = dataphish("test", seed)
        for pair in BENIGN:
            src_tr = concat(nazario("train", seed), benign(pair, "train", seed))
            src_va = concat(nazario("val", seed), benign(pair, "val", seed))
            tgt, _ = decontaminate(dp_test, src_tr)
            sv, st = all_scores(src_tr, [src_va, tgt])
            llm = b12.reindex(tgt.row_uid).values.astype(float)
            assert not np.isnan(llm).any(), f"missing {args.llm} scores ({pair}, seed {seed})"
            yv, yt = src_va.y.values, tgt.y.values
            llm_pos = llm >= LLM_CUT

            def rec(system, b, alert, escalated):
                rows.append(dict(seed=seed, pair=pair, system=system, budget=b,
                                 test_fpr=float(alert[yt == 0].mean()), recall=float(alert[yt == 1].mean()),
                                 escalation_legit=float(escalated[yt == 0].mean()),
                                 escalation_all=float(escalated.mean())))

            for b in BUDGETS:
                rec("LLM_alone", b, llm_pos, np.ones_like(llm_pos))
                for m in PREFILTERS:
                    thr = thresholds(sv[m][yv == 0], b)
                    gate = st[m] >= thresholds(sv[m][yv == 0], 8 * b)["budget"]
                    rec(f"{m}->LLM", b, gate & llm_pos, gate)
                    rec(f"{m}_alone", b, st[m] > thr["budget"], np.zeros_like(gate))
                if args.llm == "b13":                                  # S1 descriptive gate sweep (CC only)
                    for k in (2, 4, 16):
                        gate = st["CC_full"] >= thresholds(sv["CC_full"][yv == 0], k * b)["budget"]
                        rec(f"CC_full->LLM@{k}b", b, gate & llm_pos, gate)
            print(f"seed {seed} {pair}: done", flush=True)

    res = pd.DataFrame(rows)
    res.to_csv(out / "results.csv", index=False)

    g = res[res.budget == 0.01]
    m = g.groupby(["pair", "system"])[["test_fpr", "recall"]].mean()
    h1 = {p: float(m.loc[(p, "CC_full->LLM"), "test_fpr"]) for p in BENIGN}
    h2 = {}
    for p in BENIGN:
        piv = g[g.pair == p].pivot_table(index="seed", columns="system", values="test_fpr")
        others = piv[[f"{x}->LLM" for x in PREFILTERS[1:]]].min(axis=1)
        h2[p] = int((piv["CC_full->LLM"] < others).sum())
    h3 = {p: bool(m.loc[(p, "CC_full->LLM"), "recall"] >= m.loc[(p, "CC_full_alone"), "recall"]) for p in BENIGN}
    verdict = dict(H1_cc_cascade_fpr=h1, H1=all(v <= 0.02 for v in h1.values()),
                   H2_seeds_below_all_trained_cascades=h2, H2=sum(v >= 4 for v in h2.values()) >= 2,
                   H3_recall_ge_cc_alone=h3, H3=sum(h3.values()) >= 2)
    if args.llm == "b13":
        s1a = {p: dict(cascade=float(m.loc[(p, "CC_full->LLM"), "recall"]), llm_alone=float(m.loc[(p, "LLM_alone"), "recall"]))
               for p in BENIGN}
        for p in BENIGN:
            s1a[p]["met"] = s1a[p]["cascade"] >= s1a[p]["llm_alone"] - 0.03
        s1b = {p: float(m.loc[(p, "CC_full->LLM"), "test_fpr"]) for p in BENIGN}
        esc = {p: float(g[(g.pair == p) & (g.system == "CC_full->LLM")].escalation_legit.mean()) for p in BENIGN}
        verdict = dict(S1a_recall=s1a, S1a=sum(v["met"] for v in s1a.values()) >= 2,
                       S1b_fpr=s1b, S1b=all(v <= 0.01 for v in s1b.values()), escalation_legit=esc)
    commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                            cwd=Path(__file__).resolve().parents[3]).stdout.strip()
    (out / "run_manifest.json").write_text(json.dumps(dict(
        purpose=("V1" if args.llm == "b12" else "S1") + " preregistered retrieval-gated LLM cascade", llm=args.llm, seeds=args.seeds, budgets=BUDGETS,
        prefilters=PREFILTERS, llm_cut=LLM_CUT, commit=commit, criterion=verdict), indent=2))
    print(m.round(4).to_string())
    print("CRITERION", json.dumps(verdict))
    print("wrote", out)


if __name__ == "__main__":
    main()
