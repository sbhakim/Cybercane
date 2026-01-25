"""
Multi-model synthetic healthcare phishing generator with full provenance tracking.

Conference-grade implementation with:
- Multi-model generation (OpenAI, DeepSeek, Anthropic)
- Per-sample provenance (model, temperature, seed, timestamp, prompt_id)
- Quality validation gates
- Deterministic reproducibility
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd


# =============================================================================
# Template Definitions
# =============================================================================

HEALTHCARE_ATTACK_TEMPLATES: Dict[str, List[str]] = {
    "appointment_scam": [
        "Urgent: Your appointment at Johns Hopkins has been rescheduled. Confirm at secure-jhm-portal.com within 24 hours.",
        "IMPORTANT: We need to verify your upcoming surgery date. Click here: verify-medstar.net.",
        "Your COVID-19 test results are ready. View at covidresults-urgent.com.",
    ],
    "insurance_verification": [
        "Action Required: Your health insurance coverage expires soon. Update payment info at secure-bluecross-portal.com.",
        "Medicare Notification: Verify your Part D enrollment at medicare-benefits-check.org.",
        "Important: Your insurance claim #54782 requires additional information. Upload documents here.",
    ],
    "prescription_fraud": [
        "CVS Pharmacy: Your prescription is ready for pickup but payment failed. Update card at cvs-rx-secure.com.",
        "Walgreens Alert: Refill authorization needed for your medication. Respond at walgreens-verify.net.",
        "Your prescription delivery requires signature confirmation: pharma-delivery-confirm.com.",
    ],
    "ehr_credential_theft": [
        "Epic MyChart: Your account access will be suspended. Verify credentials at mychart-login-verify.com.",
        "Security Alert: Unusual activity detected on your patient portal. Secure your account now.",
        "Your electronic health records require password reset due to security upgrade.",
    ],
}

SENDER_DOMAINS = {
    "appointment_scam": [
        "noreply@johnshopkins-health.com",
        "appointments@medstar-system.net",
        "scheduler@mayoclinic-portal.com",
    ],
    "insurance_verification": [
        "benefits@bluecross-verify.com",
        "notifications@medicare-benefits.org",
        "claims@uhc-insurance.net",
    ],
    "prescription_fraud": [
        "pharmacy@cvs-rx.com",
        "refills@walgreens-pharmacy.net",
        "orders@rxdelivery-secure.com",
    ],
    "ehr_credential_theft": [
        "security@mychart-login.com",
        "support@epic-systems.net",
        "alerts@patient-portal-secure.com",
    ],
}


# =============================================================================
# LLM Client Abstractions
# =============================================================================

class LLMClient:
    """Abstract LLM client with unified interface."""

    def __init__(self, model_config: Dict[str, Any]):
        self.model_name = model_config["name"]
        self.provider = model_config["provider"]
        self.temperature = model_config["temperature"]
        self.max_tokens = model_config["max_tokens"]
        self.base_url = model_config.get("base_url")

    def generate(self, prompt: str, temperature: Optional[float] = None) -> str:
        """Generate text from prompt. Returns generated text."""
        raise NotImplementedError


class OpenAIClient(LLMClient):
    """OpenAI-compatible client (supports OpenAI and DeepSeek via base_url)."""

    def __init__(self, model_config: Dict[str, Any]):
        super().__init__(model_config)
        from openai import OpenAI

        api_key = os.getenv("OPENAI_API_KEY" if not self.base_url else "DEEPSEEK_API_KEY", "")
        if not api_key:
            raise RuntimeError(f"API key not set for {self.provider}")

        self.client = OpenAI(
            api_key=api_key,
            base_url=self.base_url
        )

    def generate(self, prompt: str, temperature: Optional[float] = None) -> str:
        temp = temperature if temperature is not None else self.temperature
        resp = self.client.chat.completions.create(
            model=self.model_name,
            messages=[{"role": "user", "content": prompt}],
            temperature=temp,
            max_tokens=self.max_tokens,
        )
        return (resp.choices[0].message.content or "").strip()


class AnthropicClient(LLMClient):
    """Anthropic Claude client."""

    def __init__(self, model_config: Dict[str, Any]):
        super().__init__(model_config)
        try:
            from anthropic import Anthropic
        except ImportError:
            raise RuntimeError("anthropic package required: pip install anthropic")

        api_key = os.getenv("ANTHROPIC_API_KEY", "")
        if not api_key:
            raise RuntimeError("ANTHROPIC_API_KEY not set")

        self.client = Anthropic(api_key=api_key)

    def generate(self, prompt: str, temperature: Optional[float] = None) -> str:
        temp = temperature if temperature is not None else self.temperature
        resp = self.client.messages.create(
            model=self.model_name,
            max_tokens=self.max_tokens,
            temperature=temp,
            messages=[{"role": "user", "content": prompt}]
        )
        return resp.content[0].text.strip()


def create_client(model_config: Dict[str, Any]) -> LLMClient:
    """Factory function to create appropriate client."""
    provider = model_config["provider"]
    if provider == "openai":
        return OpenAIClient(model_config)
    elif provider == "anthropic":
        return AnthropicClient(model_config)
    else:
        raise ValueError(f"Unknown provider: {provider}")


# =============================================================================
# Generation Functions
# =============================================================================

def _has_url(text: str) -> bool:
    """Check if text contains URL."""
    return bool(re.search(r"(https?://|www\.)\S+", text))


def _ensure_url(text: str, category: str) -> str:
    """Ensure text contains URL, add fallback if missing."""
    if _has_url(text):
        return text
    fallback = f"Visit https://{category.replace('_', '-')}-portal-update.com to confirm."
    return f"{text}\n\n{fallback}"


def _extract_url_flag(text: str) -> int:
    """Extract URL flag (0 or 1)."""
    return 1 if _has_url(text) else 0


def _compute_sample_hash(subject: str, body: str) -> str:
    """Compute deterministic hash for deduplication."""
    content = f"{subject}||{body}"
    return hashlib.sha256(content.encode()).hexdigest()


def _validate_quality(
    sample: Dict[str, Any],
    config: Dict[str, Any]
) -> tuple[bool, List[str]]:
    """
    Validate sample against quality filters.

    Returns (is_valid, rejection_reasons)
    """
    filters = config.get("quality_filters", {})
    reasons = []

    subject = sample.get("subject", "")
    body = sample.get("body", "")
    category = sample.get("category", "")

    # URL requirement
    if filters.get("url_required") and not _has_url(body):
        reasons.append("missing_url")

    # Length constraints
    if len(body) < filters.get("min_body_length", 0):
        reasons.append(f"body_too_short_{len(body)}")
    if len(body) > filters.get("max_body_length", 10000):
        reasons.append(f"body_too_long_{len(body)}")
    if len(subject) < filters.get("min_subject_length", 0):
        reasons.append(f"subject_too_short_{len(subject)}")
    if len(subject) > filters.get("max_subject_length", 1000):
        reasons.append(f"subject_too_long_{len(subject)}")

    # Category keyword presence (basic check)
    if filters.get("require_category_keywords"):
        category_keywords = {
            "appointment_scam": ["appointment", "confirm", "reschedule", "visit"],
            "insurance_verification": ["insurance", "coverage", "benefits", "claim"],
            "prescription_fraud": ["prescription", "pharmacy", "medication", "refill"],
            "ehr_credential_theft": ["account", "portal", "password", "login", "credentials"],
        }
        keywords = category_keywords.get(category, [])
        body_lower = body.lower()
        if not any(kw in body_lower for kw in keywords):
            reasons.append("missing_category_keywords")

    return (len(reasons) == 0, reasons)


def generate_phishing_email(
    client: LLMClient,
    *,
    category: str,
    template_example: str,
    index: int,
    prompt_version: str,
    config: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Generate single phishing email with full provenance.

    Returns dict with email fields + metadata.
    """
    # Body generation
    body_prompt = (
        "Generate a realistic modern phishing email for this healthcare attack category.\n"
        f"Category: {category}\n"
        f"Attack type: {config['categories'][category]['description']}\n"
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

    body = client.generate(body_prompt)
    body = _ensure_url(body, category)

    # Subject generation
    subject_prompt = (
        "Generate a 5-10 word email subject line for this phishing email body:\n\n"
        f"{body}\n\nSubject line only, no quotes."
    )
    subject = client.generate(subject_prompt, temperature=max(0.2, client.temperature - 0.2))
    subject = subject.strip().strip('"').strip("'")

    if not subject:
        subject = "Action Required: Verify your appointment"

    # Sender selection
    sender_list = SENDER_DOMAINS.get(category, [f"noreply@healthcare-{index}.com"])
    sender = sender_list[index % len(sender_list)]

    # Build sample with full provenance
    timestamp = datetime.utcnow().isoformat() + "Z"
    sample = {
        # Core fields
        "id": f"synthetic_{category}_{client.model_name.replace('/', '_')}_{index}",
        "category": category,
        "subject": subject,
        "body": body,
        "sender": sender,
        "label": 1,
        "urls": _extract_url_flag(body),

        # Provenance metadata (CRITICAL for reproducibility)
        "gen_model": client.model_name,
        "gen_provider": client.provider,
        "gen_temperature": client.temperature,
        "gen_seed": config["generation"]["seed"],
        "gen_timestamp": timestamp,
        "prompt_version": prompt_version,
        "template_id": hashlib.md5(template_example.encode()).hexdigest()[:8],
        "sample_index": index,

        # Quality tracking
        "body_length": len(body),
        "subject_length": len(subject),
        "sample_hash": _compute_sample_hash(subject, body),
    }

    return sample


# =============================================================================
# Main Generation Pipeline
# =============================================================================

def load_config(config_path: str) -> Dict[str, Any]:
    """Load generation configuration."""
    with open(config_path) as f:
        return json.load(f)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate multi-model synthetic healthcare phishing with provenance"
    )
    parser.add_argument(
        "--config",
        default="api/app/evaluation/configs/synthetic_healthcare_v1.json",
        help="Path to generation config JSON"
    )
    parser.add_argument(
        "--output",
        help="Override output CSV path (default from config)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Test clients without generating full dataset"
    )
    args = parser.parse_args()

    # Load config
    config = load_config(args.config)
    print(f"Loaded config: {config['version']}")
    print(f"Description: {config['description']}")

    # Set random seed for reproducibility
    seed = config["generation"]["seed"]
    random.seed(seed)
    print(f"Random seed: {seed}")

    # Initialize LLM clients
    print("\nInitializing LLM clients...")
    clients = []
    for model_cfg in config["generation"]["models"]:
        try:
            client = create_client(model_cfg)
            clients.append(client)
            print(f"  ✓ {client.model_name} ({client.provider})")
        except Exception as e:
            print(f"  ✗ {model_cfg['name']}: {e}")
            raise

    if args.dry_run:
        print("\n[DRY RUN] Testing client connectivity...")
        for client in clients:
            test_resp = client.generate("Say 'OK' if you can read this.", temperature=0.1)
            print(f"  {client.model_name}: {test_resp[:50]}")
        print("\n✓ Dry run complete. All clients functional.")
        return

    # Prepare output
    output_path = args.output or config["output"]["csv_path"]
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Generation loop
    rows: List[Dict[str, Any]] = []
    rejections: List[Dict[str, Any]] = []

    categories = config["categories"]
    samples_per_category = config["generation"]["samples_per_category"]
    prompt_version = config["generation"]["prompt_version"]

    total_target = len(categories) * samples_per_category
    print(f"\nTarget: {total_target} samples ({samples_per_category} per category × {len(categories)} categories)")
    print(f"Models: {len(clients)} ({', '.join(c.model_name for c in clients)})")

    start_time = time.time()

    for category in categories:
        print(f"\n{'='*80}")
        print(f"Category: {category} (target: {samples_per_category})")
        print(f"{'='*80}")

        templates = HEALTHCARE_ATTACK_TEMPLATES[category]

        for i in range(samples_per_category):
            # Round-robin model selection for diversity
            client = clients[i % len(clients)]
            template = templates[i % len(templates)]

            try:
                sample = generate_phishing_email(
                    client,
                    category=category,
                    template_example=template,
                    index=i,
                    prompt_version=prompt_version,
                    config=config,
                )

                # Quality validation
                is_valid, rejection_reasons = _validate_quality(sample, config)

                if is_valid:
                    rows.append(sample)
                    if (i + 1) % 10 == 0:
                        print(f"  Progress: {i+1}/{samples_per_category} ({client.model_name})")
                else:
                    print(f"  ✗ Rejected sample {i}: {', '.join(rejection_reasons)}")
                    rejections.append({
                        **sample,
                        "rejection_reasons": "|".join(rejection_reasons)
                    })

            except Exception as e:
                print(f"  ✗ Error generating sample {i} with {client.model_name}: {e}")
                rejections.append({
                    "category": category,
                    "index": i,
                    "model": client.model_name,
                    "error": str(e),
                    "rejection_reasons": "generation_error"
                })

        # Save progress after each category
        if rows:
            pd.DataFrame(rows).to_csv(output_path, index=False)
            print(f"  ✓ Saved {len(rows)} samples to {output_path}")

    # Final save
    df = pd.DataFrame(rows)
    df.to_csv(output_path, index=False)

    # Save rejections
    if rejections:
        rej_path = config["output"]["rejections_path"]
        pd.DataFrame(rejections).to_csv(rej_path, index=False)
        print(f"\n✓ Saved {len(rejections)} rejections to {rej_path}")

    # Summary statistics
    elapsed = time.time() - start_time
    print(f"\n{'='*80}")
    print(f"GENERATION COMPLETE")
    print(f"{'='*80}")
    print(f"✓ Generated: {len(df)} samples")
    print(f"✗ Rejected: {len(rejections)} samples")
    print(f"⏱  Time: {elapsed/60:.1f} minutes ({len(df)/elapsed:.2f} samples/sec)")

    if not df.empty:
        print(f"\n📊 Category distribution:")
        print(df["category"].value_counts().to_string())

        print(f"\n🤖 Model distribution:")
        print(df["gen_model"].value_counts().to_string())

        print(f"\n✅ Quality metrics:")
        print(f"   URLs present: {df['urls'].sum()}/{len(df)} ({df['urls'].mean()*100:.1f}%)")
        print(f"   Avg body length: {df['body_length'].mean():.0f} chars")
        print(f"   Avg subject length: {df['subject_length'].mean():.0f} chars")

        print(f"\n✓ Output: {output_path}")
        print(f"✓ Config: {args.config}")
        print(f"\nNext steps:")
        print(f"  1. Run deduplication: python -m app.evaluation.deduplicate_synthetic --input {output_path}")
        print(f"  2. Run contamination check: python -m app.evaluation.check_contamination --input {output_path}")
        print(f"  3. Generate manifest: python -m app.evaluation.generate_manifest --config {args.config}")


if __name__ == "__main__":
    main()
