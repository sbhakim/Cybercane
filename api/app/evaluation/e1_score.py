"""
E1 scoring: human audit of CyberCane's explanations (protocol fixed before any run).

Inputs: an annotation export (the Study admin JSON download, or a raw Firestore REST snapshot), the private
variant key (task_a_key.csv), the generations (task_a_generations.jsonl), and the item bundle.
Outputs (to --out): sentences.csv (one row per judged sentence, with the automated checker's label) and
e1_results.json (O1-O5 and the E1a-E1d criteria). Cluster bootstrap over emails, 10,000 resamples.

  python -m app.evaluation.e1_score --export results/cybercane_annotations_2026-10-10.json \
      [--annotator annotator@example.org] [--exclude-before 2026-10-04T15:00:00Z] --out results/e1
"""
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path

import numpy as np
import pandas as pd

from app.evaluation.groundedness_v2 import evaluate_groundedness_v2
from app.evaluation.pilot_c1_shift import WS

HA = Path(os.environ.get("CYBERCANE_ANNOT_DIR", WS / "annotations"))
B = 10_000
SEED = 20261005
TAG_RE = re.compile(r"^\s*\[([A-Z]+)\]")


# ---------------------------------------------------------------- loading
def _rest(v):
    k, x = next(iter(v.items()))
    if k == "mapValue": return {a: _rest(b) for a, b in x.get("fields", {}).items()}
    if k == "arrayValue": return [_rest(b) for b in x.get("values", [])]
    if k == "integerValue": return int(x)
    if k == "nullValue": return None
    return x


def load_responses(path: Path) -> list[dict]:
    d = json.loads(Path(path).read_text())
    rs = d["responses"]
    return [{k: _rest(v) for k, v in r["fields"].items()} if "fields" in r else r for r in rs]   # REST snapshot or app export


def bullets_of(analysis: dict) -> list[str]:          # identical to e1_explanations.bullets_of
    return [b for b in analysis["ai_reasons"] if not b.startswith("Conclusion:")]


def sentences(resp, key, gens, items, annotator=None, exclude_before=None) -> tuple[pd.DataFrame, dict]:
    kmap = key.set_index("item").to_dict("index")
    rs = [r for r in resp if r.get("task") == "A" and not r.get("practice") and r.get("item") in kmap]
    if annotator: rs = [r for r in rs if r.get("email") == annotator]
    log = dict(responses=len(rs))
    if exclude_before: rs = [r for r in rs if (r.get("saved_at") or "") >= exclude_before]
    log["after_cutoff"] = len(rs)
    flagged = [r for r in rs if r.get("flag") and r["flag"].get("reason") != "later"]
    log["flagged_excluded"] = {r["item"]: r["flag"].get("reason") for r in flagged}
    rs = [r for r in rs if r.get("complete") and not (r.get("flag") and r["flag"].get("reason") != "later")]
    log["complete_used"] = len(rs)
    rows = []
    for r in rs:
        k = kmap[r["item"]]; g = gens[(k["row_uid"], bool(k["ontology_context"]))]["analysis"]
        bl = bullets_of(g)
        assert bl == items[r["item"]]["bullets"], f"bullet mismatch for {r['item']}"
        assert len(r["labels"]) == len(bl), f"label count mismatch for {r['item']}"
        for i, (b, lab) in enumerate(zip(bl, r["labels"])):
            m = TAG_RE.match(b); tag = m.group(1) if m else "UNTAGGED"
            rows.append(dict(item=r["item"], email=k["row_uid"], cell=k["cell"], family=k["family"],
                             ontology=bool(k["ontology_context"]), idx=i, tag=tag, sentence=b, human=lab,
                             checker=evaluate_groundedness_v2(b, tag, g) if m else "UNKNOWN",
                             helpful=r.get("helpful"), consistent=r.get("consistent"), annotator=r.get("email")))
    return pd.DataFrame(rows), log


# ---------------------------------------------------------------- statistics
def _ratio(df, num):
    den = df[df.human != "NO CLAIM"]
    return float((den.human == num).mean()) if len(den) else float("nan")


def boot(df, stat, rng):
    """Percentile CI of stat(df) under cluster resampling of emails."""
    if df.empty:
        return [None, None]
    emails = df.email.unique(); groups = {e: g for e, g in df.groupby("email")}
    vals = []
    for _ in range(B):
        pick = rng.choice(emails, len(emails), replace=True)
        vals.append(stat(pd.concat([groups[e] for e in pick], ignore_index=True)))
    v = np.array(vals, dtype=float); v = v[~np.isnan(v)]
    return [float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))] if len(v) else [None, None]


def score(s: pd.DataFrame) -> dict:
    rng = np.random.default_rng(SEED)
    out = {"n_sentences": len(s), "n_emails": int(s.email.nunique()), "n_items": int(s.item.nunique())}
    a = s[s.ontology]                                                           # deployed variant (a)
    for name, lab in (("O1_support", "SUPPORTED"), ("O2_contradiction", "CONTRADICTED")):
        out[name] = dict(value=_ratio(a, lab), ci=boot(a, lambda d, lab=lab: _ratio(d, lab), rng), n=int((a.human != "NO CLAIM").sum()))
        out[name + "_by_tag"] = {t: dict(value=_ratio(g, lab), n=int((g.human != "NO CLAIM").sum())) for t, g in a.groupby("tag")}
    paired = s[s.email.isin(set(s[s.ontology].email) & set(s[~s.ontology].email))]
    if paired.email.nunique():
        for name, lab in (("O3_diff_support", "SUPPORTED"), ("O3_diff_contradiction", "CONTRADICTED")):
            f = lambda d, lab=lab: _ratio(d[d.ontology], lab) - _ratio(d[~d.ontology], lab)
            out[name] = dict(value=f(paired), ci=boot(paired, f, rng), n_emails=int(paired.email.nunique()))
    chk = s[s.checker != "UNKNOWN"]
    tp = int(((chk.checker == "SUPPORTED") & (chk.human == "SUPPORTED")).sum())
    out["O4_checker_coverage"] = float((s.checker != "UNKNOWN").mean())     # share of sentences the checker can judge
    out["O4_checker"] = dict(precision=tp / max(1, int((chk.checker == "SUPPORTED").sum())),
                             recall=tp / max(1, int((s.human == "SUPPORTED").sum())),
                             confusion=pd.crosstab(s.human, s.checker).to_dict())
    per_item = s.drop_duplicates("item")
    out["O5"] = {v: dict(helpful=g.helpful.value_counts().to_dict(), consistent=g.consistent.value_counts().to_dict())
                 for v, g in per_item.groupby(per_item.ontology.map({True: "with_ontology", False: "without_ontology"}))}
    out["O5_by_cell"] = {c: g.helpful.value_counts().to_dict() for c, g in per_item.groupby("cell")}
    ci = lambda k: out.get(k, {}).get("ci", [None, None])
    out["criteria"] = dict(
        E1a_largely_grounded=ci("O1_support")[0] is not None and ci("O1_support")[0] >= 0.80,
        E1b_rarely_wrong=ci("O2_contradiction")[1] is not None and ci("O2_contradiction")[1] <= 0.10,
        E1c_ontology_changes_accuracy=bool(ci("O3_diff_contradiction")[0] is not None and
                                           (ci("O3_diff_contradiction")[0] > 0 or ci("O3_diff_contradiction")[1] < 0)),
        E1d_checker_can_stand_in=out["O4_checker"]["precision"] >= 0.90)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--export", required=True)
    ap.add_argument("--annotator")
    ap.add_argument("--exclude-before", help="ISO time; answers saved earlier are the training phase")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    key = pd.read_csv(HA / "data" / "task_a_key.csv")
    gens = {(g["row_uid"], g["ontology_context"]): g for g in map(json.loads, (HA / "data" / "task_a_generations.jsonl").read_text().splitlines())}
    items = {x["id"]: x for x in json.loads((HA / "firebase" / "data" / "items_private.json").read_text())}
    s, log = sentences(load_responses(Path(a.export)), key, gens, items, a.annotator, a.exclude_before)
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    s.to_csv(out / "sentences.csv", index=False)
    res = dict(log=log, **(score(s) if len(s) else {"note": "no usable sentences"}))
    (out / "e1_results.json").write_text(json.dumps(res, indent=1, default=str))
    print(json.dumps(res, indent=1, default=str)[:3000])


if __name__ == "__main__":
    main()
