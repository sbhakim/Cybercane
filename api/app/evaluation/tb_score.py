"""
TB scoring: natural-identifier redaction audit from human Task B answers (protocol fixed before any run).

Leak rule = P1's preregistered rule (p1_planted_redaction.leak_tokens), applied to natural identifiers:
an identifier leaks if any alphabetic token of length >= 3 or any digit run of length >= 4 survives in the
redacted text (whole-token match). Mapping of the annotation types onto P1's exclusions:
  EMAIL          provider/TLD words excluded, as in P1 (gmail, com, outlook, yahoo, proton, company, org)
  DATE_PERSONAL  alphabetic tokens excluded (month names alone do not identify), as P1's dob
  ADDRESS        the house number counts whatever its length (P1: "house number or street name")
  IP             the dotted quad, as in P1
TB1 uses the cached redactor v2.2 output shown to the annotator; TB2 re-runs redactor v2.3 on the raw email.

  python -m app.evaluation.tb_score --export results/cybercane_annotations_2026-10-10.json \
      [--annotator annotator@example.org] [--exclude-before ISO] --out results/tb
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import numpy as np
import pandas as pd

from app.evaluation.e1_score import HA, boot, load_responses
from app.evaluation.p1_planted_redaction import SUFFIX, wilson

PROVIDER = {"gmail", "com", "outlook", "yahoo", "proton", "company", "org"}
PH = re.compile(r"\[(NAME|LOCATION|EMAIL|PHONE|ADDRESS|ZIP|DATE|ID|CARD|SSN|IP|QUERY)\]")


def leak_tokens(kind: str, value: str) -> list[str]:
    if kind == "IP":
        return [value.strip()]
    alpha = [t for t in re.findall(r"[A-Za-z]+", value) if len(t) >= 3]
    if kind == "EMAIL":
        alpha = [t for t in alpha if t.lower() not in PROVIDER]
    if kind == "DATE_PERSONAL":
        alpha = []
    digits = [t for t in re.findall(r"\d+", value) if len(t) >= 4]
    if kind == "ADDRESS":                                       # street name counts, the suffix does not (P1)
        alpha = [t for t in alpha if t.lower().rstrip(".") not in {x.lower().rstrip(".") for x in SUFFIX}]
        m = re.match(r"\s*(\d+)", value)
        if m and m.group(1) not in digits:
            digits.insert(0, m.group(1))
    return alpha + digits


def leaked(kind: str, value: str, text: str) -> list[str]:
    return [t for t in leak_tokens(kind, value) if re.search(r"(?<![A-Za-z0-9])" + re.escape(t) + r"(?![A-Za-z0-9])", text)]


def redact_v23(raw: str) -> str:
    from app.privacy.boundary import sanitize_for_external      # current code = redactor v2.3
    subj, _, body = raw.partition("\n\n")
    return sanitize_for_external(subj.replace("Subject:", "", 1).strip(), body)[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--export", required=True)
    ap.add_argument("--annotator")
    ap.add_argument("--exclude-before")
    ap.add_argument("--out", required=True)
    ap.add_argument("--no-v23", action="store_true", help="skip the v2.3 re-run (TB2)")
    a = ap.parse_args()
    items = {x["id"]: x for x in json.loads((HA / "firebase" / "data" / "items_private.json").read_text())}
    rs = [r for r in load_responses(Path(a.export)) if r.get("task") == "B" and not r.get("practice") and r.get("item") in items]
    if a.annotator: rs = [r for r in rs if r.get("email") == a.annotator]
    log = dict(responses=len(rs))
    if a.exclude_before: rs = [r for r in rs if (r.get("saved_at") or "") >= a.exclude_before]
    log["flagged_excluded"] = {r["item"]: r["flag"].get("reason") for r in rs if r.get("flag") and r["flag"].get("reason") != "later"}
    rs = [r for r in rs if r.get("complete") and not (r.get("flag") and r["flag"].get("reason") != "later")]
    log["complete_used"] = len(rs)

    ids, phs = [], []
    for r in rs:
        it = items[r["item"]]; red22 = it["redacted"]; red23 = None if a.no_v23 else redact_v23(it["raw"])
        for m in r.get("identifiers", []):
            l22 = leaked(m["type"], m["text"], red22)
            row = dict(item=r["item"], email=r["item"], type=m["type"], text=m["text"], personal=m.get("personal"),
                       tokens="|".join(leak_tokens(m["type"], m["text"])), leak_v22=bool(l22), leaked_v22="|".join(l22))
            if red23 is not None:
                l23 = leaked(m["type"], m["text"], red23); row.update(leak_v23=bool(l23), leaked_v23="|".join(l23))
            ids.append(row)
        n_ph = len(PH.findall(red22)); wm = r.get("wrong_masks", [])
        phs.append(dict(item=r["item"], email=r["item"], placeholders=n_ph, flagged=len(wm),
                        harmful=sum(w.get("harm") == "yes" for w in wm), no_identifiers=bool(r.get("no_identifiers"))))
    I, P = pd.DataFrame(ids), pd.DataFrame(phs)
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    I.to_csv(out / "identifiers.csv", index=False); P.to_csv(out / "placeholders.csv", index=False)

    rng = np.random.default_rng(20261005)
    res = dict(log=log, n_emails=len(P), n_identifiers=len(I))
    tok = I[I.tokens != ""] if len(I) else I                       # identifiers with no checkable token cannot leak
    res["uncheckable_identifiers"] = int(len(I) - len(tok))
    rate = lambda d, col: float(d[col].mean()) if len(d) else float("nan")
    for ver in ("v22",) + (() if a.no_v23 else ("v23",)):
        col = f"leak_{ver}"
        res[f"TB{1 if ver == 'v22' else 2}_{ver}"] = {
            grp: dict(leak=rate(d, col), ci=boot(d, lambda x, c=col: rate(x, c), rng), n=len(d))
            for grp, d in (("all", tok), ("personal", tok[tok.personal == "yes"]), ("company", tok[tok.personal == "no"]))}
        res[f"by_type_{ver}"] = {t: dict(leak=rate(d, col), wilson_recall=wilson(int((~d[col]).sum()), len(d)), n=len(d))
                                 for t, d in tok.groupby("type")}
    if not a.no_v23:
        pers = tok[tok.personal == "yes"]
        f = lambda d: rate(d, "leak_v23") - rate(d, "leak_v22")
        res["TBc_diff_personal_v23_minus_v22"] = dict(value=f(pers) if len(pers) else None, ci=boot(pers, f, rng))
    tot = int(P.placeholders.sum()) if len(P) else 0
    pbs = lambda d: float(d.harmful.sum() / max(1, d.placeholders.sum()))
    res["TB3"] = dict(placeholders=tot, flagged_share=float(P.flagged.sum() / max(1, tot)), harmful_share=pbs(P) if len(P) else None,
                      harmful_ci=boot(P, pbs, rng) if len(P) else [None, None])
    up = lambda k: (res.get(k, {}).get("personal", {}) or {}).get("ci", [None, None])
    res["criteria"] = dict(
        TBa_personal_largely_removed=up("TB1_v22")[1] is not None and up("TB1_v22")[1] <= 0.10,
        TBb_overredaction_rarely_harms=res["TB3"]["harmful_ci"][1] is not None and res["TB3"]["harmful_ci"][1] <= 0.05,
        TBc_v23_improves=bool(not a.no_v23 and res["TBc_diff_personal_v23_minus_v22"]["ci"][1] is not None
                              and res["TBc_diff_personal_v23_minus_v22"]["ci"][1] < 0))
    (out / "tb_results.json").write_text(json.dumps(res, indent=1, default=str))
    print(json.dumps(res, indent=1, default=str)[:2500])


if __name__ == "__main__":
    main()
