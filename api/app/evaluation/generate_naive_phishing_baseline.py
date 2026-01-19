"""
Generate naive (obvious) phishing baseline for difficulty spectrum analysis.

This script creates easily-detectable phishing emails with obvious red flags
to validate that CyberCane successfully detects unsophisticated attacks.
"""
from __future__ import annotations

import argparse
import os
import random
import re
import time
from typing import Dict, List

import pandas as pd


def _has_url(text: str) -> bool:
    return bool(re.search(r"(https?://|www\.)\S+", text))


def _build_client() -> "OpenAI":
    try:
        from openai import OpenAI
    except Exception as exc:
        raise RuntimeError("openai package is required for generation") from exc

    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not set")
    return OpenAI(api_key=api_key)


NAIVE_TEMPLATES = {
    "appointment_scam": [
        {
            "subject": "URGENT: Verify Your Appointment NOW or It Will Be CANCELLED",
            "body": "URGENT NOTICE: Your appointment with Dr. Smith will be CANCELLED unless you verify immediately. Click here within 24 hours: http://185.234.123.45/verify-appointment. Enter your password and SSN to confirm. DO NOT IGNORE THIS MESSAGE!",
            "sender": "noreply@hospital-urgent-verify.tk",
        },
        {
            "subject": "Action Required: Your Appointment Has Been Suspended",
            "body": "Dear Patient, Your upcoming appointment has been suspended due to verification issues. URGENT: Visit bit.ly/hosp-verify and provide your login credentials and date of birth immediately to avoid cancellation.",
            "sender": "admin@hospitalsystem.info",
        },
    ],
    "insurance_verification": [
        {
            "subject": "URGENT: Your Insurance Coverage Expires in 24 Hours!",
            "body": "WARNING: Your health insurance will be terminated unless you verify your information immediately. Click here: http://92.145.67.89/insurance-update and enter your SSN, credit card, and password. Act now or lose coverage!",
            "sender": "alerts@medicare-urgent.tk",
        },
        {
            "subject": "IMMEDIATE ACTION REQUIRED: Update Your Insurance Information",
            "body": "Your insurance benefits will be suspended! Verify your account at tinyurl.com/ins-verify immediately. Provide your social security number and banking details to continue coverage.",
            "sender": "notices@healthcare-benefits.biz",
        },
    ],
    "prescription_fraud": [
        {
            "subject": "URGENT: Your Prescription Payment FAILED - Update Card Now!",
            "body": "ALERT: Your prescription order payment was declined. Visit http://45.123.98.76/cvs-payment and enter your credit card number, CVV, and password within 24 hours or your medication will be cancelled!",
            "sender": "pharmacy@cvs-urgent-update.tk",
        },
        {
            "subject": "Action Required: Verify Your Prescription Delivery Address",
            "body": "Your prescription delivery is on hold. URGENT: Click bit.ly/rx-verify and provide your password, date of birth, and credit card to complete verification. Do not delay!",
            "sender": "deliveries@walgreens-pharmacy.info",
        },
    ],
    "ehr_credential_theft": [
        {
            "subject": "URGENT: Your Patient Portal Will Be LOCKED - Verify Now!",
            "body": "SECURITY ALERT: Your patient portal account will be locked in 24 hours due to suspicious activity. Visit http://198.45.123.67/portal-verify and enter your username, password, and SSN immediately to prevent account closure!",
            "sender": "security@mypatient-portal.tk",
        },
        {
            "subject": "IMMEDIATE ACTION: Reset Your EHR Password Now",
            "body": "Your electronic health records account requires urgent password reset. Click tinyurl.com/ehr-reset and provide your current password, social security number, and date of birth. Failure to act will result in account suspension!",
            "sender": "alerts@epic-mychart.biz",
        },
    ],
}


def generate_naive_phishing(category: str, index: int, model: str = "gpt-4o-mini") -> Dict[str, object]:
    """
    Generate ONE naive phishing email with obvious red flags.
    Uses templates with manual overrides to ensure detection.
    """
    templates = NAIVE_TEMPLATES.get(category, [])
    if not templates:
        raise ValueError(f"No templates for category: {category}")

    # Rotate through templates
    template = templates[index % len(templates)]

    # Add variation using LLM while preserving red flags
    client = _build_client()

    prompt = f"""Rewrite this phishing email to add minor variation while PRESERVING these critical elements:
1. Keep ALL urgency keywords (URGENT, IMMEDIATE, etc.)
2. Keep request for sensitive info (password, SSN, credit card)
3. Keep the suspicious URL/IP address
4. Keep threatening tone
5. Make only minor wording changes

Original email:
Subject: {template['subject']}
Body: {template['body']}

Output only the rewritten body (keep it similar but slightly varied). Do NOT remove red flags."""

    resp = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.3,  # Low temperature to stay close to template
        max_tokens=200,
    )

    body = (resp.choices[0].message.content or template['body']).strip()

    # Ensure URL is present (fallback to template if LLM removed it)
    if not _has_url(body):
        body = template['body']

    return {
        "id": f"naive_{category}_{index}",
        "category": category,
        "subject": template['subject'],
        "body": body,
        "label": 1,
        "source": "naive_baseline",
        "sender": template['sender'],
        "urls": 1,  # All naive emails have URLs
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate naive phishing baseline")
    parser.add_argument("--output", default="reports/naive_phishing_baseline.csv")
    parser.add_argument("--model", default="gpt-4o-mini")
    parser.add_argument("--count-per-category", type=int, default=12)  # 12*4=48 emails
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    random.seed(args.seed)
    os.makedirs(os.path.dirname(args.output), exist_ok=True)

    rows: List[Dict[str, object]] = []
    total = len(NAIVE_TEMPLATES) * args.count_per_category

    print(f"="*80)
    print(f"NAIVE PHISHING BASELINE GENERATION")
    print(f"="*80)
    print(f"Target: {total} emails ({args.count_per_category} per category)")
    print(f"Model: {args.model}, Seed: {args.seed}")
    print()

    start_ts = time.time()

    for category in NAIVE_TEMPLATES.keys():
        print(f"Generating {args.count_per_category} naive {category} emails...")
        for i in range(args.count_per_category):
            try:
                row = generate_naive_phishing(category, i, model=args.model)
                rows.append(row)
                if (i + 1) % 5 == 0:
                    print(f"  {i + 1}/{args.count_per_category} generated")
            except Exception as exc:
                print(f"  Error on {category} index {i}: {exc}")

    df = pd.DataFrame(rows)
    df.to_csv(args.output, index=False)

    elapsed = time.time() - start_ts
    print(f"\n{'='*80}")
    print(f"GENERATION COMPLETE")
    print(f"{'='*80}")
    print(f"✅ Wrote {len(df)} rows to {args.output}")
    print(f"\n📊 Category distribution:")
    print(df["category"].value_counts())
    print(f"\n✅ Red flag validation:")
    print(f"   - Emails with URLs: {df['urls'].sum()}/{len(df)}")
    print(f"   - Average body length: {df['body'].str.len().mean():.0f} chars")
    print(f"\n⏱  Total time: {elapsed:.1f} seconds")
    print(f"\n🎯 PURPOSE: Baseline to validate system detects obvious phishing")


if __name__ == "__main__":
    main()
