"""
Generate synthetic healthcare phishing emails using an LLM.

This script produces a labeled phishing-only dataset across several
healthcare attack categories. Output is a CSV suitable for evaluation.
"""
from __future__ import annotations

import argparse
import os
import random
import re
import time
from typing import Dict, List

import pandas as pd


HEALTHCARE_ATTACK_TEMPLATES: Dict[str, Dict[str, object]] = {
    "appointment_scam": {
        "count": 50,
        "description": "Impersonate healthcare providers requesting urgent appointment confirmation/rescheduling via malicious links.",
        "examples": [
            "Urgent: Your appointment at Johns Hopkins has been rescheduled. Confirm at secure-jhm-portal.com within 24 hours.",
            "IMPORTANT: We need to verify your upcoming surgery date. Click here: verify-medstar.net.",
            "Your COVID-19 test results are ready. View at covidresults-urgent.com.",
        ],
    },
    "insurance_verification": {
        "count": 50,
        "description": "Fake insurance benefits verification, coverage confirmation, or card updates.",
        "examples": [
            "Action Required: Your health insurance coverage expires soon. Update payment info at secure-bluecross-portal.com.",
            "Medicare Notification: Verify your Part D enrollment at medicare-benefits-check.org.",
            "Important: Your insurance claim #54782 requires additional information. Upload documents here.",
        ],
    },
    "prescription_fraud": {
        "count": 50,
        "description": "Pharmacy impersonation requesting verification, payment, or delivery confirmation.",
        "examples": [
            "CVS Pharmacy: Your prescription is ready for pickup but payment failed. Update card at cvs-rx-secure.com.",
            "Walgreens Alert: Refill authorization needed for your medication. Respond at walgreens-verify.net.",
            "Your prescription delivery requires signature confirmation: pharma-delivery-confirm.com.",
        ],
    },
    "ehr_credential_theft": {
        "count": 50,
        "description": "Fake EHR/patient portal login pages to steal credentials.",
        "examples": [
            "Epic MyChart: Your account access will be suspended. Verify credentials at mychart-login-verify.com.",
            "Security Alert: Unusual activity detected on your patient portal. Secure your account now.",
            "Your electronic health records require password reset due to security upgrade.",
        ],
    },
}


def _has_url(text: str) -> bool:
    return bool(re.search(r"(https?://|www\.)\S+", text))


def _ensure_url(text: str, category: str) -> str:
    if _has_url(text):
        return text
    fallback = f"Visit https://{category.replace('_', '-')}-portal-update.com to confirm."
    return f"{text}\n\n{fallback}"


def _extract_url_flag(text: str) -> int:
    return 1 if _has_url(text) else 0


def _build_client() -> "OpenAI":
    try:
        from openai import OpenAI
    except Exception as exc:
        raise RuntimeError("openai package is required for generation") from exc

    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not set")
    return OpenAI(api_key=api_key)


def generate_phishing_email(
    client: "OpenAI",
    *,
    category: str,
    template_example: str,
    index: int,
    model: str,
    temperature: float,
) -> Dict[str, object]:
    prompt = (
        "Generate a realistic modern phishing email for this healthcare attack category.\n"
        f"Category: {category}\n"
        f"Attack type: {HEALTHCARE_ATTACK_TEMPLATES[category]['description']}\n"
        f"Example template: {template_example}\n\n"
        "Requirements:\n"
        "1) Create a DIFFERENT phishing email (not identical to example)\n"
        "2) Use realistic healthcare/medical terminology\n"
        "3) Include urgency tactics (e.g., 'within 24 hours', 'urgent')\n"
        "4) Include a suspicious URL (typosquatted domain or suspicious subdomain)\n"
        "5) 2-4 sentences, professional tone\n"
        "6) Target elderly/vulnerable patient populations\n"
        "7) Make it convincing enough to fool someone in a hurry\n\n"
        "Output ONLY the email body text, no subject line, no explanations."
    )

    resp = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=temperature,
        max_tokens=220,
    )
    body = (resp.choices[0].message.content or "").strip()
    body = _ensure_url(body, category)

    subj_prompt = (
        "Generate a 5-10 word email subject line for this phishing email body:\n\n"
        f"{body}\n\nSubject line only, no quotes."
    )
    subj_resp = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": subj_prompt}],
        temperature=max(0.2, temperature - 0.2),
        max_tokens=40,
    )
    subject = (subj_resp.choices[0].message.content or "").strip().strip('"')
    if not subject:
        subject = "Action Required: Verify your appointment"

    # Realistic typosquatted healthcare sender domains
    sender_domains = {
        "appointment_scam": [
            "noreply@johnshopkins-health.com",  # typosquat of johnshopkins.org
            "appointments@medstar-system.net",  # typosquat of medstarhealth.org
            "scheduler@mayoclinic-portal.com",  # typosquat of mayoclinic.org
        ],
        "insurance_verification": [
            "benefits@bluecross-verify.com",    # typosquat of bcbs.com
            "notifications@medicare-benefits.org",  # typosquat of medicare.gov
            "claims@uhc-insurance.net",         # typosquat of uhc.com
        ],
        "prescription_fraud": [
            "pharmacy@cvs-rx.com",              # typosquat of cvs.com
            "refills@walgreens-pharmacy.net",   # typosquat of walgreens.com
            "orders@rxdelivery-secure.com",
        ],
        "ehr_credential_theft": [
            "security@mychart-login.com",       # typosquat of mychart domains
            "support@epic-systems.net",         # typosquat of epic.com
            "alerts@patient-portal-secure.com",
        ],
    }

    sender_list = sender_domains.get(category, [f"noreply@healthcare-{index}.com"])
    sender = sender_list[index % len(sender_list)]

    return {
        "id": f"synthetic_{category}_{index}",
        "category": category,
        "subject": subject,
        "body": body,
        "label": 1,
        "source": "gpt4_synthetic",
        "sender": sender,
        "urls": _extract_url_flag(body),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic healthcare phishing emails")
    parser.add_argument("--output", default="reports/synthetic_healthcare_phishing.csv")
    parser.add_argument("--model", default="gpt-4o-mini")
    parser.add_argument("--temperature", type=float, default=0.8)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--count-per-category", type=int, default=None)
    parser.add_argument(
        "--save-every",
        type=int,
        default=10,
        help="Write intermediate results every N generated emails",
    )
    args = parser.parse_args()

    random.seed(args.seed)
    client = _build_client()

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    rows: List[Dict[str, object]] = []
    total_target = sum(int(args.count_per_category or cfg["count"]) for cfg in HEALTHCARE_ATTACK_TEMPLATES.values())

    # API cost tracking (gpt-4o-mini pricing: $0.150/1M input, $0.600/1M output)
    total_api_calls = total_target * 2  # body + subject
    estimated_tokens = total_target * (150 + 220 + 40)  # prompt + body + subject
    estimated_cost = (estimated_tokens / 1_000_000) * 0.375  # average of input/output

    print(f"Target total: {total_target} emails")
    print(f"Estimated API calls: {total_api_calls} (~${estimated_cost:.2f})")
    print(f"Model: {args.model}, Temperature: {args.temperature}, Seed: {args.seed}")

    start_ts = time.time()
    last_report_ts = start_ts

    def report_progress(force: bool = False) -> None:
        nonlocal last_report_ts
        now = time.time()
        if not force and (now - last_report_ts) < 60:
            return
        last_report_ts = now
        elapsed = max(0.001, now - start_ts)
        done = len(rows)
        rate = done / elapsed
        remaining = max(0, total_target - done)
        eta = remaining / rate if rate > 0 else 0.0
        by_cat: Dict[str, int] = {}
        for r in rows:
            c = str(r.get("category", "unknown"))
            by_cat[c] = by_cat.get(c, 0) + 1
        by_cat_str = ", ".join(f"{k}={v}" for k, v in sorted(by_cat.items()))
        try:
            size_kb = os.path.getsize(args.output) / 1024.0 if os.path.exists(args.output) else 0.0
        except Exception:
            size_kb = 0.0
        print(
            f"[progress] {done}/{total_target} generated "
            f"({rate:.2f}/s, eta {eta/60:.1f} min) "
            f"file={args.output} ({size_kb:.1f} KB) "
            f"by_category: {by_cat_str}",
            flush=True,
        )

    for category, cfg in HEALTHCARE_ATTACK_TEMPLATES.items():
        count = int(args.count_per_category or cfg["count"])
        examples: List[str] = list(cfg["examples"])  # type: ignore[assignment]
        print(f"Generating {count} emails for {category}...")

        for i in range(count):
            seed_example = examples[i % len(examples)]
            try:
                row = generate_phishing_email(
                    client,
                    category=category,
                    template_example=seed_example,
                    index=i,
                    model=args.model,
                    temperature=args.temperature,
                )
                rows.append(row)
                if (i + 1) % 10 == 0:
                    print(f"  {i + 1}/{count} generated", flush=True)
                if args.save_every > 0 and len(rows) % args.save_every == 0:
                    pd.DataFrame(rows).to_csv(args.output, index=False)
                    report_progress(force=True)
                else:
                    report_progress()
            except Exception as exc:
                print(f"  Error on {category} index {i}: {exc}", flush=True)
                report_progress()

        # Save after each category
        pd.DataFrame(rows).to_csv(args.output, index=False)
        report_progress(force=True)

    df = pd.DataFrame(rows)
    df.to_csv(args.output, index=False)

    # Quality validation
    print(f"\n{'='*80}")
    print(f"GENERATION COMPLETE")
    print(f"{'='*80}")
    print(f"✅ Wrote {len(df)} rows to {args.output}")

    if not df.empty:
        print(f"\n📊 Category distribution:")
        print(df["category"].value_counts())

        print(f"\n✅ Quality checks:")
        urls_present = df["urls"].sum()
        print(f"   - Emails with URLs: {urls_present}/{len(df)} ({urls_present/len(df)*100:.1f}%)")

        empty_subjects = df["subject"].isna().sum() + (df["subject"] == "").sum()
        print(f"   - Non-empty subjects: {len(df) - empty_subjects}/{len(df)}")

        empty_bodies = df["body"].isna().sum() + (df["body"] == "").sum()
        print(f"   - Non-empty bodies: {len(df) - empty_bodies}/{len(df)}")

        avg_body_len = df["body"].str.len().mean()
        print(f"   - Average body length: {avg_body_len:.0f} chars")

        elapsed = time.time() - start_ts
        print(f"\n⏱  Total time: {elapsed/60:.1f} minutes ({len(df)/elapsed:.2f} emails/sec)")
        print(f"💰 Estimated cost: ~${estimated_cost:.2f}")

        if urls_present < len(df) * 0.9:
            print(f"\n⚠️  WARNING: Only {urls_present/len(df)*100:.1f}% of emails have URLs (expected >90%)")
        if empty_subjects > len(df) * 0.05:
            print(f"⚠️  WARNING: {empty_subjects} emails have empty subjects")


if __name__ == "__main__":
    main()
