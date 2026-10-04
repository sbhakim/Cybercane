"""
P1: planted-identifier redaction audit.

Protocol and success criteria were fixed before the run (P1, preregistration table in the paper).
Synthetic identifiers with known ground truth are planted into real test emails
(cued and uncued contexts) and each planting is sanitized independently by the
privacy boundary (redactor v2.2: patterns + local NER on CPU). Only the text
between two sentinel lines around the planted sentence is scored, so identifiers
already present in the base email never count. A missing sentinel is recorded as
an error, never as a pass. Phishing signals (brand, URL host, reply domain) are
planted the same way to measure what the boundary keeps.

Usage:
  CUDA_VISIBLE_DEVICES="" PYTHONPATH=api python -m app.evaluation.p1_planted_redaction --workers 12
"""

import argparse
import json
import os
import random
import re
import subprocess
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

WS = Path(os.environ.get("CYBERCANE_WS", Path(__file__).resolve().parents[3] / "workspace"))
S0, S1 = "QXZSTARTMARK", "QXZENDMARK"
SEED = 20261003

FIRST = ["James", "Emily", "Michael", "Sarah", "Robert", "Jennifer", "Carlos", "Lucia", "Alejandro", "Mariana",
         "Diego", "Valentina", "Priya", "Rahul", "Ananya", "Vikram", "Lakshmi", "Arjun", "Wei", "Mei", "Hiroshi",
         "Yuki", "Jin", "Hana", "Mohammed", "Fatima", "Omar", "Aisha", "Yusuf", "Layla", "Chinedu", "Ngozi",
         "Kwame", "Amara", "Tendai", "Zainab", "Olivia", "Daniel", "Sofia", "Mateo"]
LAST = ["Smith", "Johnson", "Williams", "Brown", "Miller", "Davis", "Garcia", "Rodriguez", "Hernandez", "Lopez",
        "Martinez", "Gonzalez", "Patel", "Sharma", "Iyer", "Reddy", "Gupta", "Nair", "Wang", "Li", "Tanaka",
        "Nakamura", "Kim", "Park", "Khan", "Hassan", "Rahman", "Haddad", "Okafor", "Adeyemi", "Mensah", "Mwangi",
        "Moyo", "Abubakar", "Nguyen", "Tran", "Kowalski", "Novak", "Rossi", "Murphy"]
STREETS = ["Maple", "Oakwood", "Cedar Ridge", "Elm", "Willow Creek", "Highland", "Lakeview", "Sunset", "Franklin",
           "Riverside", "Chestnut", "Hillcrest", "Magnolia", "Pinecrest", "Washington"]
SUFFIX = ["Street", "Avenue", "Road", "Lane", "Drive", "Court", "Boulevard", "Way", "Circle", "Highway"]
CITIES = [("Baltimore", "MD"), ("Austin", "TX"), ("Columbus", "OH"), ("Fresno", "CA"), ("Tampa", "FL")]
MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October",
          "November", "December"]
BRANDS = [("PayPal", "paypa1-secure.com", "paypal-support.net"), ("Microsoft", "micros0ft-login.net", "office365-alerts.com"),
          ("Amazon", "amazon-billing-update.com", "amazon-orders.info"), ("Apple", "appleid-verify.info", "icloud-help.org"),
          ("Netflix", "netflix-account-help.com", "netflix-billing.net"), ("DHL", "dhl-parcel-track.org", "dhl-delivery.info"),
          ("Wells Fargo", "wellsfargo-alerts.co", "wf-secure-mail.com"), ("Chase", "chase-secure-login.us", "chase-notices.net"),
          ("DocuSign", "docusign-review.net", "docusign-envelope.com"), ("Coinbase", "coinbase-wallet-support.com", "coinbase-help.org")]

CUED = {
    "name": "Dear {v}, thank you for your message.",
    "email": "You can reach me at {v} if anything changes.",
    "phone": "Please call me at {v} this afternoon.",
    "ssn": "My social security number is {v} for the form.",
    "address": "Please ship the package to {v} by Friday.",
    "dob": "Date of birth: {v}.",
    "card": "Card number: {v}, expiring next year.",
    "account": "Account number: {v}.",
    "mrn": "MRN: {v}.",
    "ip": "We saw a login from IP address {v}.",
}
UNCUED = {
    "name": "{v} will follow up tomorrow.",
    "email": "{v} was copied on this thread.",
    "phone": "Use {v} after five.",
    "ssn": "Noted: {v}.",
    "address": "We met at {v} last week.",
    "dob": "That was on {v}.",
    "card": "Noted: {v}.",
    "account": "Noted: {v}.",
    "mrn": "Noted: {v}.",
    "ip": "Noted: {v}.",
}
STRUCTURED = ("email", "phone", "ssn", "dob", "card", "account", "mrn", "ip")


def luhn_card(rng):
    d = [4] + [rng.randrange(10) for _ in range(14)]
    s = 0
    for i, x in enumerate(reversed(d)):
        y = x * 2 if i % 2 == 0 else x
        s += y - 9 if y > 9 else y
    d.append((10 - s % 10) % 10)
    g = "".join(map(str, d))
    sep = rng.choice([" ", "-", ""])
    return sep.join(g[i:i + 4] for i in range(0, 16, 4))


def make_value(kind, rng):
    if kind == "name":
        return f"{rng.choice(FIRST)} {rng.choice(LAST)}"
    if kind == "email":
        return f"{rng.choice(FIRST).lower()}.{rng.choice(LAST).lower()}{rng.randrange(10, 99)}@" + \
            rng.choice(["gmail.com", "outlook.com", "yahoo.com", "proton.me", "company.org"])
    if kind == "phone":
        a, b, c = rng.randrange(201, 989), rng.randrange(200, 999), rng.randrange(1000, 9999)
        return rng.choice([f"({a}) {b}-{c}", f"{a}-{b}-{c}", f"{a}.{b}.{c}", f"+1 {a} {b} {c}"])
    if kind == "ssn":
        return f"{rng.randrange(100, 665):03d}-{rng.randrange(1, 99):02d}-{rng.randrange(1, 9999):04d}"
    if kind == "address":
        city, st = rng.choice(CITIES)
        return f"{rng.randrange(12, 9899)} {rng.choice(STREETS)} {rng.choice(SUFFIX)}, {city}, {st} {rng.randrange(10000, 99999)}"
    if kind == "dob":
        y, m, d = rng.randrange(1940, 2005), rng.randrange(1, 13), rng.randrange(1, 28)
        return rng.choice([f"{m:02d}/{d:02d}/{y}", f"{MONTHS[m - 1]} {d}, {y}", f"{y}-{m:02d}-{d:02d}", f"{d} {MONTHS[m - 1]} {y}"])
    if kind == "card":
        return luhn_card(rng)
    if kind == "account":
        return str(rng.randrange(10 ** 7, 10 ** 12))
    if kind == "mrn":
        return rng.choice([str(rng.randrange(10 ** 6, 10 ** 8)), f"A{rng.randrange(10 ** 6, 10 ** 7)}"])
    if kind == "ip":
        return ".".join(str(rng.randrange(1, 255)) for _ in range(4))
    raise ValueError(kind)


def leak_tokens(kind, value):
    """Tokens whose survival counts as a leak (preregistered rule)."""
    if kind == "address":
        num, street = re.match(r"(\d+) (.+?) (?:%s)," % "|".join(SUFFIX), value).groups()
        return [num] + [t for t in street.split() if len(t) >= 3]
    alpha = [t for t in re.findall(r"[A-Za-z]+", value) if len(t) >= 3]
    if kind == "email":
        alpha = [t for t in alpha if t.lower() not in {"gmail", "com", "outlook", "yahoo", "proton", "company", "org"}]
    if kind == "dob":
        alpha = []                               # month names alone do not identify
    digits = [t for t in re.findall(r"\d+", value) if len(t) >= 4]
    if kind == "ip":
        digits = [value]                         # an IP leaks if the dotted quad survives
    return alpha + digits


def insertion_point(body):
    m = re.search(r"[.!?]\s", body[:1500])
    return m.end() if m else 0


def plant(body, sentence):
    i = insertion_point(body)
    return body[:i] + f"\n{S0}\n{sentence}\n{S1}\n" + body[i:]


def build_tasks():
    rng = random.Random(SEED)
    base = []
    for fam in ("dataphish", "nazsa"):
        d = pd.read_csv(WS / "datasets_v2" / f"{fam}_seed42_test.csv")
        for lab in ("phishing", "legit"):
            base.append(d[d.fine == lab].sample(50, random_state=SEED).assign(family=fam))
    base = pd.concat(base, ignore_index=True)
    tasks = []
    for i, r in base.iterrows():
        subj, body = str(r.subject if isinstance(r.subject, str) else ""), str(r.body if isinstance(r.body, str) else "")
        for kind in CUED:
            for ctx, tmpl in (("cued", CUED[kind]), ("uncued", UNCUED[kind])):
                v = make_value(kind, rng)
                tasks.append(dict(email=i, family=r.family, label=r.fine, kind=kind, context=ctx, value=v,
                                  subject=subj, body=plant(body, tmpl.format(v=v))))
        brand, host, dom = BRANDS[i % len(BRANDS)]
        sent = f"Sign in to your {brand} account at https://{host}/verify or reply to support@{dom}."
        tasks.append(dict(email=i, family=r.family, label=r.fine, kind="signals", context="cued",
                          value=json.dumps([brand, host, dom]), subject=subj, body=plant(body, sent)))
    return tasks


def run_one(t):
    os.environ.setdefault("CUDA_VISIBLE_DEVICES", "")
    from app.privacy.boundary import sanitize_for_external
    text, rep = sanitize_for_external(t["subject"], t["body"])
    pos = (t["subject"] + "\n\n" + t["body"]).find(S0)
    out = dict(email=t["email"], family=t["family"], label=t["label"], kind=t["kind"], context=t["context"],
               value=t["value"], ner_used=rep.ner_used, plant_pos=pos)
    # NER word-piece merging can absorb a sentinel fragment into an adjacent entity
    # span ("QXZSTARTMAR[NAME]", "[LOCATION]XZENDMARK"). The inner fragments below
    # always survive in that case, so the segment is recovered from them; a row is
    # lost only if even these are missing (documented deviation).
    a0, a1 = text.find(S0[1:-1]), text.find(S1[1:-1])
    if a0 < 0 or a1 < 0 or a1 < a0:
        out.update(status="sentinel_lost")
        return out
    seg = text[a0 + len(S0) - 2:a1]
    seg = re.sub(r"^[KQ]", "", seg.lstrip("K")).rsplit("\n", 1)[0] if seg.count("\n") else seg
    out["sentinel_exact"] = S0 in text and S1 in text
    out["segment"] = seg.strip()
    if t["kind"] == "signals":
        brand, host, dom = json.loads(t["value"])
        out.update(status="ok", brand_kept=brand in seg, host_kept=host in seg, domain_kept=dom in seg)
    else:
        toks = leak_tokens(t["kind"], t["value"])
        leaked = [tok for tok in toks if re.search(r"(?<![A-Za-z0-9])" + re.escape(tok) + r"(?![A-Za-z0-9])", seg)]
        out.update(status="ok", leaked=bool(leaked), leaked_tokens="|".join(leaked))
    return out


def wilson(k, n, z=1.96):
    if n == 0:
        return (np.nan, np.nan)
    p = k / n
    c = (p + z * z / (2 * n)) / (1 + z * z / n)
    h = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return (c - h, c + h)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=12)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--tag", default="", help="output prefix tag, e.g. v23_ for a post-fix re-audit")
    args = ap.parse_args()
    tasks = build_tasks()
    if args.limit:
        tasks = tasks[:args.limit]
    out = WS / "reports_v2" / f"p1_planted_{args.tag}{datetime.now():%Y%m%d_%H%M%S}"
    out.mkdir(parents=True, exist_ok=True)
    with ProcessPoolExecutor(args.workers) as ex:
        rows = list(ex.map(run_one, tasks, chunksize=8))
    res = pd.DataFrame(rows)
    res.to_csv(out / "results.csv", index=False)
    assert res.ner_used.all(), "NER unavailable for some rows; refusing to report"
    assert (res.plant_pos.between(0, 6000)).all(), "a planting fell outside the 8000-char window"
    lost = int((res.status != "ok").sum())

    ids = res[(res.kind != "signals") & (res.status == "ok")].copy()
    ids["leaked"] = ids.leaked.astype(bool)   # mixed-type column (NaN on signal rows): ~ would bit-flip ints
    table = []
    for (kind, ctx), g in ids.groupby(["kind", "context"]):
        k = int((~g.leaked).sum()); n = len(g); lo, hi = wilson(k, n)
        table.append(dict(kind=kind, context=ctx, n=n, recall=k / n, lo=lo, hi=hi))
    tab = pd.DataFrame(table)
    tab.to_csv(out / "recall_by_type.csv", index=False)
    groups = ["Anglo"] * 6 + ["Hispanic"] * 5 + ["South Asian"] * 6 + ["East Asian"] * 5 + ["Arabic"] * 6 + \
        ["African"] * 6 + ["Anglo", "Anglo", "Hispanic", "Hispanic"]
    origin = dict(zip(FIRST, groups))
    nm = ids[ids.kind == "name"].copy()
    nm["origin"] = nm.value.str.split().str[0].map(origin)
    nm.groupby(["origin", "context"]).leaked.agg(n="size", recall=lambda x: 1 - x.mean()).reset_index() \
        .to_csv(out / "name_recall_by_origin.csv", index=False)
    sig = res[(res.kind == "signals") & (res.status == "ok")]
    struct = ids[ids.kind.isin(STRUCTURED)]
    verdict = dict(
        sentinel_lost=lost,
        structured_recall={c: float((~g.leaked).mean()) for c, g in struct.groupby("context")},
        structured_all_ge_99=bool((tab[tab.kind.isin(STRUCTURED)].recall >= 0.99).all()),
        failing_structured=tab[(tab.kind.isin(STRUCTURED)) & (tab.recall < 0.99)][["kind", "context", "recall"]].to_dict("records"),
        name_recall={c: float((~g.leaked).mean()) for c, g in ids[ids.kind == "name"].groupby("context")},
        address_recall={c: float((~g.leaked).mean()) for c, g in ids[ids.kind == "address"].groupby("context")},
        signals_kept=dict(brand=float(sig.brand_kept.mean()), host=float(sig.host_kept.mean()),
                          domain=float(sig.domain_kept.mean())))
    commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                            cwd=Path(__file__).resolve().parents[3]).stdout.strip()
    (out / "run_manifest.json").write_text(json.dumps(dict(
        purpose="P1 preregistered planted-identifier redaction audit", seed=SEED, tag=args.tag,
        redactor_version=__import__("app.privacy.redactor", fromlist=["x"]).REDACTOR_VERSION, n_tasks=len(tasks),
        ner_model=os.getenv("CYBERCANE_NER_MODEL", "dslim/bert-base-NER"), commit=commit, verdict=verdict), indent=2))
    print(tab.round(3).to_string(index=False))
    print("VERDICT", json.dumps(verdict))
    print("wrote", out)


if __name__ == "__main__":
    main()
