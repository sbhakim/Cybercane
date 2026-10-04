"""
E1 + E2: gap-closing experiments.

Protocol and success criteria were fixed before the run (E1 + E2, preregistration table in the paper).
  E1  CyberCane x zero-shot LLM: ECDF-average fusion (primary) and a
      retrieval-first cascade (secondary). SpamAssassin pair only (B12 scores).
  E2  CSLS-style correction with unlabeled mail from each domain:
      s'(x) = n(x) - mean top-k cosine of x to its own domain's unlabeled pool.
CPU only; uses cached embeddings and cached B12 responses; no provider calls.

Usage:
  CUDA_VISIBLE_DEVICES="" PYTHONPATH=api python -m app.evaluation.e1_e2_gap_closing
"""

import argparse
import json
import subprocess
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

from app.evaluation.llm_zero_shot import CACHE_FILE as B12_CACHE
from app.evaluation.pilot_c1_shift import BUDGETS, PHASE1_SIGNAL, WS, fit_scorers
from app.evaluation.r2_benign_shift import BENIGN, benign, dataphish, decontaminate, nazario
from app.evaluation.r5_style_shift import concat
from app.evaluation.replicate_c1 import thresholds
from app.evaluation.replicate_c1_decontam import cluster_boot_fpr

K_CSLS = 8
CASCADE_BAND = 8  # uncertain band: between the budget and 8x budget CC thresholds


def topk_mean_sim(X: np.ndarray, pool: np.ndarray, k: int) -> np.ndarray:
    out = np.empty(len(X))
    for s in range(0, len(X), 1000):
        S = X[s:s + 1000] @ pool.T
        out[s:s + 1000] = np.partition(S, -k, axis=1)[:, -k:].mean(axis=1)
    return out


def ecdf(ref: np.ndarray):
    ref = np.sort(ref)
    return lambda s: np.searchsorted(ref, s, side="right") / len(ref)


def eval_scores(tag, pair, seed, sv, st, val, test, rng, extra=None):
    rows = []
    yv, yt, grp = val.y.values, test.y.values, test.cgroup.values
    nneg, npos = int((yt == 0).sum()), int((yt == 1).sum())
    for m, s_t in st.items():
        auroc = roc_auc_score(yt, s_t)
        pauc = roc_auc_score(yt, s_t, max_fpr=0.02)
        for b in BUDGETS:
            for rule, thr in thresholds(sv[m][yv == 0], b).items():
                if rule == "zero_fp" and b != BUDGETS[0]:
                    continue
                pred = s_t > thr
                fp, tp = int(pred[yt == 0].sum()), int(pred[yt == 1].sum())
                lo, hi = cluster_boot_fpr(pred[yt == 0], grp[yt == 0], rng)
                rows.append(dict(exp=tag, pair=pair, seed=seed, method=m, rule=rule,
                                 budget=b if rule != "zero_fp" else None, test_fpr=fp / nneg,
                                 boot_lo=lo, boot_hi=hi, recall=tp / npos, auroc=auroc, pauc2=pauc,
                                 n_neg=nneg, n_pos=npos, **(extra or {})))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, nargs="+", default=[42, 1, 2, 3, 4])
    args = ap.parse_args()
    out = WS / "reports_v2" / f"e1_e2_{datetime.now():%Y%m%d_%H%M%S}"
    out.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(0)

    b12 = pd.DataFrame([json.loads(l) for l in B12_CACHE.read_text().splitlines()])
    b12 = b12[b12.status == "ok"].drop_duplicates("row_uid", keep="last").set_index("row_uid").prob

    rows, cascade_rows = [], []
    for seed in args.seeds:
        dp_test = dataphish("test", seed)
        dp_pool = dataphish("train", seed)            # target unlabeled pool (labels unused)
        for pair in BENIGN:
            src_tr = concat(nazario("train", seed), benign(pair, "train", seed))
            src_va = concat(nazario("val", seed), benign(pair, "val", seed))
            tgt, _ = decontaminate(dp_test, src_tr)
            score = fit_scorers(src_tr)
            sv_all, st_all = score(src_va), score(tgt)

            # ---------------- E2: CSLS with each domain's unlabeled pool ----------------
            r_val = topk_mean_sim(src_va.attrs["X"], src_tr.attrs["X"], K_CSLS)
            r_tgt = topk_mean_sim(tgt.attrs["X"], dp_pool.attrs["X"], K_CSLS)
            n_val, n_tgt = sv_all["CC_retrieval"], st_all["CC_retrieval"]
            p_val = src_va.phase1.map(PHASE1_SIGNAL).values
            p_tgt = tgt.phase1.map(PHASE1_SIGNAL).values
            c_val, c_tgt = n_val - r_val, n_tgt - r_tgt
            sv = {"CC_retrieval": n_val, "CC_full": sv_all["CC_full"], "E2_csls": c_val,
                  "E2_csls_full": np.maximum(c_val, 0.7 * c_val + 0.3 * p_val)}
            st = {"CC_retrieval": n_tgt, "CC_full": st_all["CC_full"], "E2_csls": c_tgt,
                  "E2_csls_full": np.maximum(c_tgt, 0.7 * c_tgt + 0.3 * p_tgt)}
            rows += eval_scores("E2", pair, seed, sv, st, src_va, tgt, rng)

            # ---------------- E1: CC x LLM (SpamAssassin pair only) ----------------
            if pair == "spamassassin":
                lv = b12.reindex(src_va.row_uid).values.astype(float)
                lt = b12.reindex(tgt.row_uid).values.astype(float)
                assert not np.isnan(lv).any() and not np.isnan(lt).any(), "missing B12 scores"
                ccv, cct = sv_all["CC_full"], st_all["CC_full"]
                neg = src_va.y.values == 0
                f_cc, f_llm = ecdf(ccv[neg]), ecdf(lv[neg])
                fused_v = 0.5 * (f_cc(ccv) + f_llm(lv))
                fused_t = 0.5 * (f_cc(cct) + f_llm(lt))
                rows += eval_scores("E1", pair, seed,
                                    {"CC_full": ccv, "B12_llm": lv, "E1_fusion": fused_v},
                                    {"CC_full": cct, "B12_llm": lt, "E1_fusion": fused_t},
                                    src_va, tgt, rng)
                yt, grp = tgt.y.values, tgt.cgroup.values
                for b in BUDGETS:
                    t_b = thresholds(ccv[neg], b)["budget"]
                    t_lo = thresholds(ccv[neg], min(CASCADE_BAND * b, 0.5))["budget"]
                    band = (cct > t_lo) & (cct <= t_b)
                    pred = (cct > t_b) | (band & (lt >= 50))
                    lo, hi = cluster_boot_fpr(pred[yt == 0], grp[yt == 0], rng)
                    cascade_rows.append(dict(exp="E1", pair=pair, seed=seed, method="E1_cascade",
                                             rule="budget", budget=b, test_fpr=pred[yt == 0].mean(),
                                             boot_lo=lo, boot_hi=hi, recall=pred[yt == 1].mean(),
                                             llm_call_fraction=band.mean()))
            print(f"seed {seed} {pair}: done", flush=True)

    res = pd.concat([pd.DataFrame(rows), pd.DataFrame(cascade_rows)], ignore_index=True)
    res.to_csv(out / "results.csv", index=False)

    # Preregistered criteria
    b1 = res[(res.exp == "E1") & (res.rule == "budget") & (res.budget == 0.01)]
    ok = []
    for _, h in b1[b1.method != "E1_cascade"].groupby("seed"):
        h = h.set_index("method")
        best_rec = max(h.loc["CC_full", "recall"], h.loc["B12_llm", "recall"])
        max_fpr = max(h.loc["CC_full", "test_fpr"], h.loc["B12_llm", "test_fpr"])
        ok.append(h.loc["E1_fusion", "recall"] >= best_rec + 0.03 and h.loc["E1_fusion", "test_fpr"] <= max_fpr)
    e1 = dict(seeds_meeting=int(sum(ok)), met=bool(sum(ok) >= 4))
    e2 = []
    b2 = res[(res.exp == "E2") & (res.rule == "budget") & (res.budget == 0.01)]
    for pair, h in b2.groupby("pair"):
        m = h.groupby("method")[["test_fpr", "recall"]].mean()
        e2.append(dict(pair=pair, fpr_cc=m.loc["CC_retrieval", "test_fpr"], fpr_csls=m.loc["E2_csls", "test_fpr"],
                       rec_cc=m.loc["CC_retrieval", "recall"], rec_csls=m.loc["E2_csls", "recall"],
                       meets=bool(m.loc["E2_csls", "test_fpr"] <= 0.5 * m.loc["CC_retrieval", "test_fpr"]
                                  and m.loc["E2_csls", "recall"] >= m.loc["CC_retrieval", "recall"] - 0.05)))
    verdict = dict(E1=e1, E2=dict(pairs=e2, met=sum(p["meets"] for p in e2) >= 2))
    commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                            cwd=Path(__file__).resolve().parents[3]).stdout.strip()
    (out / "run_manifest.json").write_text(json.dumps(dict(
        purpose="E1 + E2 preregistered gap-closing", seeds=args.seeds, k_csls=K_CSLS,
        cascade_band=CASCADE_BAND, commit=commit, criterion=verdict), indent=2, default=float))
    print("CRITERION", json.dumps(verdict, default=float))
    print("wrote", out)


if __name__ == "__main__":
    main()
