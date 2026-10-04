"""
S3: standards-conformant sender-authentication checks (protocol fixed before any run).

Re-scores the 320 E1-pool emails (180 legitimate, 140 phishing) under auth_policy="strict" (deployed default)
and auth_policy="rfc" (implicit MX, DMARC organizational-domain fallback, failed lookups = unknown) in the same
run, with live DNS, the calibrated 1% thresholds, and the E1 retrieval (exact search over train phishing).

Run (project env, OPENAI_API_KEY set for the query embeddings):
  RISK_THRESHOLDS_PATH=../config/risk_thresholds_nazario_spamassassin_seed42.json \
    python -m app.evaluation.s3_auth_policy
"""
from __future__ import annotations

import collections
import json
from datetime import datetime, timezone

import pandas as pd

from app.evaluation import e1_explanations as E          # reuses E1's retrieval, memoized DNS, thresholds
from app.pipeline.deterministic import score_email
from app.pipeline.pii import redact
from app.schemas import RedactionsOut, ScanOut

OUT = E.WS / "reports_v2" / f"s3_auth_policy_{datetime.now():%Y%m%d_%H%M%S}"


def phase1(r: dict, policy: str) -> ScanOut:
    body, counts = redact(r["body"])                        # same order as classify_email: redact, then score
    d = score_email(sender=r["sender"], subject=r["subject"], body=body, url_flag=int(r["urls"]),
                    allowed_brand_domains=[], rule_weights=None, enable_dns_checks=True, auth_policy=policy)
    return ScanOut(verdict=d.verdict, score=d.score, reasons=d.reasons, indicators=d.indicators,
                   redactions=RedactionsOut(types=counts, count=sum(counts.values())), redacted_body=body)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    pool = [json.loads(l) for l in E.POOL.read_text().splitlines()]
    rows = []
    for i, r in enumerate(pool):
        nb = E.nearest_neighbors(E.service._embed_text(E.service.sanitize_for_external(r["subject"], r["body"])[0]), E.K)
        for policy in ("strict", "rfc"):
            p1 = phase1(r, policy)
            risk = E.service._compute_ai_risk(p1, nb)
            rows.append(dict(row_uid=r["row_uid"], family=r["family"], label=r["label"], policy=policy,
                             sender_domain=p1.indicators.get("sender_domain", ""), phase1=p1.verdict, risk=risk,
                             verdict=E.service.decide(risk, p1.verdict, E.service.RISK_THRESHOLDS),
                             reasons=" | ".join(p1.reasons), auth=json.dumps(p1.indicators.get("auth", {}))))
        if i % 40 == 0:
            print(f"{i + 1}/{len(pool)}", flush=True)
    df = pd.DataFrame(rows)
    df.to_csv(OUT / "results.csv", index=False)

    fp = {p: int(((df.policy == p) & (df.label == "legit") & (df.verdict == "phishing")).sum()) for p in ("strict", "rfc")}
    tp = {p: int(((df.policy == p) & (df.label == "phishing") & (df.verdict == "phishing")).sum()) for p in ("strict", "rfc")}
    n_legit, n_phish = int((df[df.policy == "strict"].label == "legit").sum()), int((df[df.policy == "strict"].label == "phishing").sum())
    reasons = {p: collections.Counter(x for s in df[df.policy == p].reasons for x in s.split(" | ") if x) for p in ("strict", "rfc")}
    remaining = df[(df.policy == "rfc") & (df.label == "legit") & (df.verdict == "phishing")]
    verdict = dict(n_legit=n_legit, n_phish=n_phish, legit_flagged_phishing=fp, phish_flagged_phishing=tp,
                   S3a=fp["rfc"] <= 0.70 * fp["strict"], S3b=tp["strict"] - tp["rfc"] <= 2,
                   reasons={p: dict(c.most_common(12)) for p, c in reasons.items()},
                   remaining_fp_domains=remaining.sender_domain.value_counts().to_dict())
    (OUT / "run_manifest.json").write_text(json.dumps(dict(
        purpose="S3 preregistered standards-conformant auth checks", run_utc=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        thresholds=str(E.service.RISK_THRESHOLDS), criterion=verdict), indent=2))
    print("CRITERION", json.dumps(verdict, indent=1))
    print("wrote", OUT)


if __name__ == "__main__":
    main()
