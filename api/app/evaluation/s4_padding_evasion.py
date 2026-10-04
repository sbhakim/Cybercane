"""
S4: robustness to benign-text padding (retrieval-dilution evasion). Protocol fixed before any run.

R2 forward shift (SpamAssassin / CEAS / Ling-Spam -> decontaminated DataPhish 2025 test), seeds 42, 1-4.
Detectors and 1%-budget thresholds are fit on clean source data exactly as in R2/V1; nothing is refit.
Each target *phishing* email gets benign padding (DataPhish legitimate *train* mail, fixed seed) appended at
length ratio r in {0.5, 1, 2}; the padded text is re-embedded (text-embedding-3-small, cached on disk).
Phase 1 outputs are kept from the clean email (stated simplification). Outcome: recall retention.

  CUDA_VISIBLE_DEVICES="" PYTHONPATH=api python -m app.evaluation.s4_padding_evasion
"""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

from app.evaluation.embed_cache_v2 import _embed_openai
from app.evaluation.pilot_c1_shift import WS, load
from app.evaluation.r2_benign_shift import BENIGN, EMBED, all_scores, benign, dataphish, decontaminate, nazario
from app.evaluation.r5_style_shift import concat
from app.evaluation.replicate_c1 import thresholds

RATIOS = (0.5, 1.0, 2.0)
PAD_SEED = 20261005
DETECTORS = ("CC_full", "CC_retrieval", "B3_tfidf_lr", "B9_emb_lr", "B10_knn_2class", "B11_tfidf_phishonly_knn")
CACHE = WS / "cache_v2" / "s4_padded_embeddings.jsonl"


class EmbCache:
    def __init__(self):
        self.d = {}
        if CACHE.exists():
            for l in CACHE.read_text().splitlines():
                r = json.loads(l); self.d[r["h"]] = np.asarray(r["v"], dtype=np.float32)

    def get(self, texts: list[str]) -> np.ndarray:
        hs = [hashlib.sha256(t.encode("utf-8", "replace")).hexdigest()[:32] for t in texts]
        todo = [(h, t) for h, t in dict(zip(hs, texts)).items() if h not in self.d]
        if todo:
            vecs = _embed_openai([t for _, t in todo], EMBED)
            with CACHE.open("a") as f:
                for (h, _), v in zip(todo, vecs):
                    self.d[h] = v; f.write(json.dumps({"h": h, "v": [round(float(x), 7) for x in v]}) + "\n")
        return np.vstack([self.d[h] for h in hs])


def padding_pool(seed: int) -> list[str]:
    d = load("dataphish", "train", "phish", EMBED, seed=seed)
    return [t for t in d[d.y == 0].sanitized.tolist() if t.strip()]


def pad(text: str, r: float, pool: list[str], rng: np.random.Generator) -> str:
    need = int(round(r * len(text))); buf = ""
    while len(buf) < need:
        buf += ("\n\n" if buf else "") + pool[int(rng.integers(len(pool)))]
    return text + "\n\n" + buf[:need]


def padded_frame(tgt: pd.DataFrame, r: float, pool, cache: EmbCache, seed: int) -> pd.DataFrame:
    rng = np.random.default_rng([PAD_SEED, seed, int(r * 10)])
    out = tgt.copy(); X = tgt.attrs["X"].copy()
    idx = np.flatnonzero(tgt.y.values == 1)
    texts = [pad(tgt.sanitized.iloc[i], r, pool, rng) for i in idx]
    out.loc[out.index[idx], "sanitized"] = texts
    X[idx] = cache.get(texts)
    out.attrs = {"X": X}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, nargs="+", default=[42, 1, 2, 3, 4])
    args = ap.parse_args()
    out = WS / "reports_v2" / f"s4_padding_evasion_{datetime.now():%Y%m%d_%H%M%S}"
    out.mkdir(parents=True, exist_ok=True)
    cache, rows = EmbCache(), []
    for seed in args.seeds:
        dp_test, pool = dataphish("test", seed), padding_pool(seed)
        for pair in BENIGN:
            src_tr = concat(nazario("train", seed), benign(pair, "train", seed))
            src_va = concat(nazario("val", seed), benign(pair, "val", seed))
            tgt, _ = decontaminate(dp_test, src_tr)
            pads = [padded_frame(tgt, r, pool, cache, seed) for r in RATIOS]
            sv, st, *sp = all_scores(src_tr, [src_va, tgt, *pads])
            yv, yt = src_va.y.values, tgt.y.values
            for m in DETECTORS:
                thr = thresholds(sv[m][yv == 0], 0.01)["budget"]
                clean = float((st[m][yt == 1] > thr).mean())
                rows.append(dict(seed=seed, pair=pair, detector=m, ratio=0.0, recall=clean, retention=1.0,
                                 test_fpr=float((st[m][yt == 0] > thr).mean())))
                for r, s in zip(RATIOS, sp):
                    rec = float((s[m][yt == 1] > thr).mean())
                    rows.append(dict(seed=seed, pair=pair, detector=m, ratio=r, recall=rec,
                                     retention=rec / clean if clean else float("nan"), test_fpr=float((s[m][yt == 0] > thr).mean())))
            print(f"seed {seed} {pair}: done", flush=True)
    res = pd.DataFrame(rows); res.to_csv(out / "results.csv", index=False)
    m = res.groupby(["pair", "detector", "ratio"])[["recall", "retention", "test_fpr"]].mean()
    r1 = res[res.ratio == 1.0].groupby(["pair", "detector"]).retention.mean()
    s4a = {p: dict(cc=float(r1[(p, "CC_full")]), b9=float(r1[(p, "B9_emb_lr")]), b10=float(r1[(p, "B10_knn_2class")])) for p in BENIGN}
    for p in BENIGN:
        s4a[p]["met"] = s4a[p]["cc"] >= max(s4a[p]["b9"], s4a[p]["b10"])
    s4b = {p: float(r1[(p, "CC_full")]) for p in BENIGN}
    verdict = dict(S4a_retention_r1=s4a, S4a=sum(v["met"] for v in s4a.values()) >= 2,
                   S4b_cc_retention_r1=s4b, S4b=sum(v >= 0.5 for v in s4b.values()) >= 2)
    (out / "run_manifest.json").write_text(json.dumps(dict(purpose="S4 preregistered padding evasion", seeds=args.seeds,
                                                           ratios=RATIOS, pad_seed=PAD_SEED, criterion=verdict), indent=2))
    print(m.round(4).to_string()); print("CRITERION", json.dumps(verdict)); print("wrote", out)


if __name__ == "__main__":
    main()
