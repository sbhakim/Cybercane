"""
Leak-free splits for additional benign corpora (R2).

CEAS_08 ham (random 4,000, seed 42, drawn before dedup) and Ling ham (all).
Same grouping, split, and leak check as `build_splits_v2`.

Usage:
  PYTHONPATH=api python -m app.evaluation.build_splits_benign_extra --seeds 42 1 2 3 4
"""

import argparse
import json

import pandas as pd

from .build_splits_v2 import OUT, RAW, assign_groups, leak_check, split

CEAS_SAMPLE = 4000


def load_ceas_ham() -> pd.DataFrame:
    c = pd.read_csv(RAW / "CEAS_08.csv")
    c = c[c.label == 0].sample(n=CEAS_SAMPLE, random_state=42)
    return pd.DataFrame(dict(source="ceas", sender=c.sender, subject=c.subject, body=c.body,
                             urls=c.urls.fillna(0).astype(int).clip(0, 1), fine="legit", creator="Human"))


def load_ling_ham() -> pd.DataFrame:
    l = pd.read_csv(RAW / "Ling.csv")
    l = l[l.label == 0]
    return pd.DataFrame(dict(source="ling", sender="", subject=l.subject, body=l.body,
                             urls=0, fine="legit", creator="Human"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, nargs="+", default=[42])
    args = ap.parse_args()
    manifest_path = OUT / "split_manifest_benign_extra.json"
    manifest = dict(ceas_sample=CEAS_SAMPLE, families={})
    for family, loader in (("ceas", load_ceas_ham), ("ling", load_ling_ham)):
        df, stats = assign_groups(loader().reset_index(drop=True))
        fam = dict(dedup=stats, seeds={})
        for seed in args.seeds:
            col = f"split_seed{seed}"
            df[col] = split(df, seed)
            leaks = leak_check(df, col)
            assert all(v["shared_groups"] == 0 and v["shared_hashes"] == 0 for v in leaks.values()), leaks
            fam["seeds"][seed] = dict(leak_check=leaks, counts=df[col].value_counts().to_dict())
            for s in ("train", "val", "test"):
                part = df[df[col] == s].drop(columns=[c for c in df.columns if c.startswith("split_seed")])
                part.to_csv(OUT / f"{family}_seed{seed}_{s}.csv", index=False)
        manifest["families"][family] = fam
        print(family, json.dumps(stats), fam["seeds"][args.seeds[0]]["counts"])
    manifest_path.write_text(json.dumps(manifest, indent=2, default=str))
    print("wrote", manifest_path)


if __name__ == "__main__":
    main()
