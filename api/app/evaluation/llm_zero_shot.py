"""
B12: zero-shot LLM baseline via OpenRouter.

Protocol and success criteria were fixed before the run (B12, preregistration table in the paper).
Only privacy-boundary text (redactor v2.2 cache) is sent. Responses are cached
by (row_uid, model, prompt version), so reruns never pay twice.

Usage:
  PYTHONPATH=api python -m app.evaluation.llm_zero_shot score --limit 20      # pilot
  PYTHONPATH=api python -m app.evaluation.llm_zero_shot score                 # all rows
  PYTHONPATH=api python -m app.evaluation.llm_zero_shot evaluate
"""

import argparse
import json
import os
import re
import subprocess
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

from app.evaluation.pilot_c1_shift import BUDGETS, WS, load
from app.evaluation.replicate_c1 import thresholds
from app.evaluation.replicate_c1_decontam import XDUP, cluster_boot_fpr, cross_max_sim

# Defaults reproduce B12. A second model (B13) is selected by environment variables;
# each model has its own cache file, so runs never mix.
MODEL = os.getenv("CYBERCANE_LLM_MODEL", "openai/gpt-oss-120b")
# One serving stack for reproducibility: one provider, bf16 weights, no fallback.
PROVIDER = {"order": [os.getenv("CYBERCANE_LLM_PROVIDER", "deepinfra")],
            "quantizations": [os.getenv("CYBERCANE_LLM_QUANT", "bf16")], "allow_fallbacks": False}
REASONING = MODEL.startswith("openai/gpt-oss")      # reasoning effort applies to gpt-oss only
METHOD = os.getenv("CYBERCANE_LLM_METHOD", "B12_gptoss120b_zeroshot")
OUT_PREFIX = os.getenv("CYBERCANE_LLM_OUT_PREFIX", "b12_llm_zero_shot_")
PROMPT_VERSION = "b12_v1"
MAX_CHARS = 3000
BUDGET_ABORT_USD = float(os.getenv("CYBERCANE_LLM_BUDGET_USD", "4.00"))
SEEDS = (42, 1, 2, 3, 4)
EMBED = "text-embedding-3-small"
CACHE_FILE = WS / "cache_v2" / f"llm_{MODEL.replace('/', '_')}_{PROMPT_VERSION}.jsonl"

PROMPT = """You are an email security analyst. Decide whether the email below is a phishing attempt \
(it tries to steal credentials, money, or personal information, or to make the recipient click a \
malicious link or open a malicious attachment) or a legitimate email. Personal identifiers have been \
replaced with placeholders such as [NAME], [EMAIL], [PHONE], and [ID]; do not treat placeholders \
themselves as suspicious.

Respond with JSON only, in exactly this form:
{{"phishing_probability": <integer 0-100>, "verdict": "phishing" or "legitimate", "reason": "<one sentence>"}}

EMAIL:
{email}"""

_JSON_RE = re.compile(r"\{.*\}", re.S)


DEFAULT_SETS = (("dataphish", "test"), ("nazsa", "val"))


def collect_rows(sets=DEFAULT_SETS) -> pd.DataFrame:
    frames = []
    for seed in SEEDS:
        for fam, split in sets:
            d = load(fam, split, "phish", EMBED, seed=seed)[["row_uid", "sanitized"]].copy()
            d.attrs = {}  # drop the embedding matrix; pandas compares attrs on concat
            frames.append(d)
    rows = pd.concat(frames, ignore_index=True).drop_duplicates("row_uid")
    rows.attrs = {}
    return rows.reset_index(drop=True)


def _call(key: str, text: str) -> dict:
    body = json.dumps({
        "model": MODEL, "temperature": 0, "max_tokens": 700,
        **({"reasoning": {"effort": "low"}} if REASONING else {}), "usage": {"include": True}, "provider": PROVIDER,
        "messages": [{"role": "user", "content": PROMPT.format(email=text[:MAX_CHARS])}],
    }).encode()
    req = urllib.request.Request("https://openrouter.ai/api/v1/chat/completions", data=body,
                                 headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=120))


def _parse(content: str):
    m = _JSON_RE.search(content or "")
    if not m:
        return None
    try:
        obj = json.loads(m.group(0))
        p = int(round(float(obj["phishing_probability"])))
        return dict(prob=max(0, min(100, p)), verdict=str(obj.get("verdict", "")).lower(),
                    reason=str(obj.get("reason", ""))[:300])
    except Exception:
        return None


def score(limit: int | None, workers: int, sets=DEFAULT_SETS) -> None:
    key = os.environ["OPENROUTER_API_KEY"]
    done = {}
    if CACHE_FILE.exists():
        for line in CACHE_FILE.read_text().splitlines():
            r = json.loads(line)
            done[r["row_uid"]] = r
    spent = sum(json.loads(l).get("cost", 0.0) for l in CACHE_FILE.read_text().splitlines()) if CACHE_FILE.exists() else 0.0
    rows = collect_rows(sets)
    if os.getenv("CYBERCANE_LLM_SAME_ROWS_AS"):          # B13: exactly the rows B12 scored
        ref = {json.loads(l)["row_uid"] for l in Path(os.environ["CYBERCANE_LLM_SAME_ROWS_AS"]).read_text().splitlines()}
        extra = [(f, s_) for f, s_ in (("ceas", "val"), ("ling", "val"))]
        rows = pd.concat([rows, collect_rows(tuple(extra))]).drop_duplicates("row_uid")
        rows = rows[rows.row_uid.isin(ref)].reset_index(drop=True)
        assert len(rows) == len(ref), (len(rows), len(ref))
    # Rows whose cached call failed (e.g. rate limits) are retried; successes are never paid for twice.
    todo = rows[~rows.row_uid.isin([u for u, r in done.items() if r.get("status") == "ok"])]
    if limit:
        todo = todo.head(limit)
    print(f"rows total {len(rows)}, cached {len(done)}, to score {len(todo)}, spent so far ${spent:.4f}", flush=True)

    lock = threading.Lock()
    state = {"spent": spent, "n": 0, "fail": 0, "abort": False}

    def work(uid, text):
        if state["abort"]:
            return None
        rec = dict(row_uid=uid, model=MODEL, prompt_version=PROMPT_VERSION, cost=0.0)
        for attempt in range(6):
            try:
                r = _call(key, text)
                u = r.get("usage", {})
                rec["cost"] += float(u.get("cost") or 0.0)
                rec.update(provider=r.get("provider"), tok_in=u.get("prompt_tokens"), tok_out=u.get("completion_tokens"))
                parsed = _parse(r["choices"][0]["message"].get("content"))
                if parsed:
                    rec.update(parsed, status="ok")
                    return rec
                rec["status"] = "unparsed"
            except Exception as exc:
                rec["status"] = f"error: {str(exc)[:120]}"
                time.sleep(min(60, 2 ** (attempt + 1)) if "429" in str(exc) else 2 * (attempt + 1))
        return rec

    with ThreadPoolExecutor(max_workers=workers) as ex, open(CACHE_FILE, "a") as fh:
        futs = [ex.submit(work, r.row_uid, r.sanitized) for r in todo.itertuples()]
        for f in as_completed(futs):
            rec = f.result()
            if rec is None:
                continue
            with lock:
                fh.write(json.dumps(rec) + "\n")
                fh.flush()
                state["spent"] += rec["cost"]
                state["n"] += 1
                state["fail"] += rec["status"] != "ok"
                if state["spent"] > BUDGET_ABORT_USD and not state["abort"]:
                    state["abort"] = True
                    print(f"ABORT: spent ${state['spent']:.4f} > ${BUDGET_ABORT_USD}", flush=True)
                if state["n"] % 250 == 0:
                    print(f"  scored {state['n']}/{len(todo)} failures {state['fail']} spent ${state['spent']:.4f}", flush=True)
    print(f"done: scored {state['n']}, failures {state['fail']}, total spent ${state['spent']:.4f}", flush=True)


def evaluate() -> None:
    cache = pd.DataFrame([json.loads(l) for l in CACHE_FILE.read_text().splitlines()]).drop_duplicates(
        "row_uid", keep="last").set_index("row_uid")
    out = WS / "reports_v2" / f"{OUT_PREFIX}{datetime.now():%Y%m%d_%H%M%S}"
    out.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(0)
    rows, fails = [], []
    for seed in SEEDS:
        train = load("nazsa", "train", "phish", EMBED, seed=seed)
        val = load("nazsa", "val", "phish", EMBED, seed=seed)
        test = load("dataphish", "test", "phish", EMBED, seed=seed)
        msim = cross_max_sim(test, train)
        bad = set(test.group[msim >= XDUP])
        test = test[~test.group.isin(bad)].reset_index(drop=True)

        def probs(df):
            c = cache.reindex(df.row_uid)
            ok = (c.status == "ok").values
            return c.prob.values.astype(float), ok

        pv, okv = probs(val)
        pt, okt = probs(test)
        fails.append(dict(seed=seed, val_fail=int((~okv).sum()), test_fail=int((~okt).sum()),
                          test_rows=len(test)))
        # Failures are scored as 50 (undecided), and also counted.
        pv, pt = np.where(okv, pv, 50.0), np.where(okt, pt, 50.0)
        yv, yt, grp = val.y.values, test.y.values, test.group.values
        nneg, npos = int((yt == 0).sum()), int((yt == 1).sum())

        def add(rule, budget, thr):
            pred = pt >= thr if rule == "default" else pt > thr
            fp, tp = int(pred[yt == 0].sum()), int(pred[yt == 1].sum())
            lo, hi = cluster_boot_fpr(pred[yt == 0], grp[yt == 0], rng)
            rows.append(dict(seed=seed, method=METHOD, rule=rule, budget=budget,
                             test_fpr=fp / nneg, boot_lo=lo, boot_hi=hi, recall=tp / npos,
                             fp=fp, n_neg=nneg, n_pos=npos, threshold=thr))

        add("default", None, 50.0)
        for b in BUDGETS:
            for rule, thr in thresholds(pv[yv == 0], b).items():
                if rule == "zero_fp" and b != BUDGETS[0]:
                    continue
                add(rule, b if rule != "zero_fp" else None, float(thr))
    pd.DataFrame(rows).to_csv(out / "results.csv", index=False)
    pd.DataFrame(fails).to_csv(out / "failures.csv", index=False)
    commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                            cwd=Path(__file__).resolve().parents[3]).stdout.strip()
    (out / "run_manifest.json").write_text(json.dumps(dict(
        purpose="B12 preregistered zero-shot LLM baseline", model=MODEL, prompt_version=PROMPT_VERSION,
        max_chars=MAX_CHARS, provider_pin=PROVIDER, seeds=SEEDS, xdup=XDUP, total_cost_usd=float(cache.cost.sum()),
        providers=cache.provider.value_counts().to_dict(), commit=commit), indent=2, default=str))
    print("wrote", out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", choices=["score", "evaluate"])
    ap.add_argument("--limit", type=int)
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--sets", nargs="+", help="family:split pairs to score, e.g. ceas:val ling:val")
    args = ap.parse_args()
    sets = tuple(tuple(x.split(":")) for x in args.sets) if args.sets else DEFAULT_SETS
    score(args.limit, args.workers, sets) if args.stage == "score" else evaluate()


if __name__ == "__main__":
    main()
