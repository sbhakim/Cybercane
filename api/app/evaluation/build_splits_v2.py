"""
Leak-free, group-aware dataset splits.

Pipeline per corpus family (Nazario+SpamAssassin, DataPhish):
  1. Normalize subject+body (lowercase, URLs -> host, collapse whitespace).
  2. Exact duplicates share a group (sha256 of normalized text).
  2b. Rewrite families (DataPhish "Original email No.") share a group.
  3. Near-duplicates (TF-IDF char 3-5-gram cosine >= NEAR_DUP) are merged into
     the same group with union-find.
  4. Group-aware stratified split 70/10/20, so no group spans two splits.

Outputs (WS/datasets_v2/):
  {family}_seed{S}_{split}.csv  and  split_manifest.json

Usage:
  PYTHONPATH=api python -m app.evaluation.build_splits_v2 --seeds 42 1 2 3 4
"""

import argparse
import hashlib
import json
import os
import re
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import StratifiedGroupKFold

from .label_policy import fine_class

WS = Path(os.environ.get("CYBERCANE_WS", Path(__file__).resolve().parents[3] / "workspace"))
RAW = WS / "datasets"
OUT = WS / "datasets_v2"
NEAR_DUP = 0.90
SPLIT_FOLDS = 10  # 7 train / 1 val / 2 test folds -> 70/10/20

_URL_RE = re.compile(r"https?://([^/\s]+)\S*", re.I)
_WS_RE = re.compile(r"\s+")


def normalize(subject: str, body: str) -> str:
    text = f"{subject or ''} \n {body or ''}".lower()
    text = _URL_RE.sub(lambda m: m.group(1), text)
    return _WS_RE.sub(" ", text).strip()


def load_nazario_spamassassin() -> pd.DataFrame:
    naz = pd.read_csv(RAW / "Nazario.clean.csv")
    spam = pd.read_csv(RAW / "SpamAssasin.csv")
    rows = []
    for _, r in naz.iterrows():
        rows.append(dict(source="nazario", sender=r.get("sender_email") or r.get("sender"),
                         subject=r.get("subject"), body=r.get("body"),
                         urls=int(r.get("urls", 0) or 0),
                         fine=fine_class("nazario", r), creator="Human"))
    for _, r in spam.iterrows():
        rows.append(dict(source="spamassassin", sender=r.get("sender"),
                         subject=r.get("subject"), body=r.get("body"),
                         urls=int(r.get("urls", 0) or 0),
                         fine=fine_class("spamassassin", r), creator="Human"))
    return pd.DataFrame(rows)


def _url_flag(value) -> int:
    # DataPhish "URL(s)" holds 0/1, a URL string, or null.
    if value is None:
        return 0
    s = str(value).strip()
    if s in ("", "0", "0.0", "nan"):
        return 0
    return 1


def load_dataphish() -> pd.DataFrame:
    rows = []
    with open(RAW / "dataphish_2025.jsonl", encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            rows.append(dict(source="dataphish", sender=r.get("Sender"),
                             subject=r.get("Subject"), body=r.get("Body"),
                             urls=_url_flag(r.get("URL(s)")),
                             fine=fine_class("dataphish", r),
                             creator=r.get("Created by"),
                             emotions=json.dumps(r.get("LLM detected emotion")),
                             orig_id=r.get("No."),
                             family_key=f"dp{r.get('Original email No.')}"))
    return pd.DataFrame(rows)


class _UF:
    def __init__(self, n):
        self.p = np.arange(n)

    def find(self, a):
        while self.p[a] != a:
            self.p[a] = self.p[self.p[a]]
            a = self.p[a]
        return a

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[rb] = ra


def assign_groups(df: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    df = df.copy()
    df["norm"] = [normalize(s, b) for s, b in zip(df.subject, df.body)]
    df = df[df.norm.str.len() > 0].reset_index(drop=True)
    df["text_hash"] = [hashlib.sha256(t.encode()).hexdigest() for t in df.norm]

    uf = _UF(len(df))
    # Exact duplicates
    first = {}
    for i, h in enumerate(df.text_hash):
        if h in first:
            uf.union(first[h], i)
        else:
            first[h] = i
    n_exact_pairs = len(df) - len(first)

    # Rewrite families (DataPhish: 1 human original + 3 LLM rewrites share a key)
    n_family_links = 0
    if "family_key" in df.columns:
        head = {}
        for i, k in enumerate(df.family_key):
            if k in head:
                uf.union(head[k], i)
                n_family_links += 1
            else:
                head[k] = i

    # Near duplicates on unique texts
    uniq_idx = np.array(sorted(first.values()))
    vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2,
                          max_features=200_000, sublinear_tf=True)
    X = vec.fit_transform(df.norm.iloc[uniq_idx])
    n_near_links = 0
    step = 2000
    for start in range(0, X.shape[0], step):
        sims = (X[start:start + step] @ X.T).tocoo()
        mask = (sims.data >= NEAR_DUP) & (sims.row + start < sims.col)
        for r, c in zip(sims.row[mask] + start, sims.col[mask]):
            uf.union(uniq_idx[r], uniq_idx[c])
            n_near_links += 1

    df["group"] = [uf.find(i) for i in range(len(df))]
    stats = dict(rows=len(df), exact_duplicate_rows=int(n_exact_pairs),
                 near_dup_links=int(n_near_links),
                 family_links=int(n_family_links), groups=int(df.group.nunique()))
    return df, stats


def split(df: pd.DataFrame, seed: int) -> pd.Series:
    sgkf = StratifiedGroupKFold(n_splits=SPLIT_FOLDS, shuffle=True, random_state=seed)
    fold = np.empty(len(df), dtype=int)
    for k, (_, idx) in enumerate(sgkf.split(df, df.fine, groups=df.group)):
        fold[idx] = k
    return pd.Series(np.where(fold < 7, "train", np.where(fold < 8, "val", "test")), index=df.index)


def leak_check(df: pd.DataFrame, col: str) -> dict:
    out = {}
    for a, b in [("train", "val"), ("train", "test"), ("val", "test")]:
        ga = set(df.loc[df[col] == a, "group"])
        gb = set(df.loc[df[col] == b, "group"])
        ha = set(df.loc[df[col] == a, "text_hash"])
        hb = set(df.loc[df[col] == b, "text_hash"])
        fa = fb = set()
        if "family_key" in df.columns:
            fa = set(df.loc[df[col] == a, "family_key"])
            fb = set(df.loc[df[col] == b, "family_key"])
        out[f"{a}-{b}"] = dict(shared_groups=len(ga & gb), shared_hashes=len(ha & hb),
                               shared_families=len(fa & fb))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, nargs="+", default=[42])
    args = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    manifest = dict(near_dup_threshold=NEAR_DUP, split="70/10/20 StratifiedGroupKFold", families={})

    for family, loader in [("nazsa", load_nazario_spamassassin), ("dataphish", load_dataphish)]:
        df, stats = assign_groups(loader())
        fam = dict(dedup=stats, seeds={})
        for seed in args.seeds:
            col = f"split_seed{seed}"
            df[col] = split(df, seed)
            leaks = leak_check(df, col)
            assert all(v["shared_groups"] == 0 and v["shared_hashes"] == 0 and v["shared_families"] == 0 for v in leaks.values()), leaks
            counts = df.groupby([col, "fine"]).size().unstack(fill_value=0).to_dict(orient="index")
            fam["seeds"][seed] = dict(leak_check=leaks, counts=counts)
            for s in ("train", "val", "test"):
                part = df[df[col] == s].drop(columns=[c for c in df.columns if c.startswith("split_seed")])
                part.to_csv(OUT / f"{family}_seed{seed}_{s}.csv", index=False)
        manifest["families"][family] = fam
        print(family, json.dumps(stats))

    (OUT / "split_manifest.json").write_text(json.dumps(manifest, indent=2, default=str))
    print("wrote", OUT / "split_manifest.json")


if __name__ == "__main__":
    main()
