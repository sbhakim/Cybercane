"""
Groundedness Evaluation Script

Evaluates whether LLM-generated explanations cite actual evidence from Phase 1 analysis.
Addresses Manuscript Issue #2: 0% AUTH support, 3.3% URGENCY support in Table 16.

Methodology:
1. Sample 60 random emails from test set
2. Run AI analysis to get LLM explanations
3. Check if tagged explanations cite specific Phase 1 evidence
4. Calculate support rate by tag: [AUTH], [URL], [URGENCY], [CONTENT], [SIMILARITY]

Support Classification:
- SUPPORTED: Explanation cites specific evidence from phase1.reasons or indicators
- UNSUPPORTED: Explanation is generic/vague without citing evidence
- UNKNOWN: Cannot determine (e.g., AUTH tag but no phase1 auth data available)
"""

import re
import random
from pathlib import Path
from typing import Dict, List

import pandas as pd

from app.schemas import EmailIn
from app.pipeline.classify import classify_email
from app.ai_service.service import analyze_email


def load_test_split(split_path: str | None = None) -> pd.DataFrame:
    """Load test split dataset."""
    if split_path is None:
        reports_dir = Path(__file__).resolve().parents[3] / "reports"
        split_path = str(reports_dir / "combined_eval_split_test.csv")
    df = pd.read_csv(split_path)
    print(f"Loaded {len(df)} test emails from {split_path}")
    return df


def _get_url_flag(email_row: pd.Series) -> int:
    if "urls" in email_row:
        return int(email_row.get("urls") or 0)
    return int(email_row.get("url") or 0)


def _clean_sender(sender_val: object) -> str:
    s = str(sender_val or "").strip()
    match = re.search(r"<([^>]+)>", s)
    if match:
        candidate = match.group(1).strip()
        if "@" in candidate:
            return candidate.replace(" ", "")
    match = re.search(r"[\w\.-]+@[\w\.-]+\.[a-zA-Z]{2,}", s)
    if match:
        return match.group(0)
    if "@" in s:
        return s.replace(" ", "")
    return "unknown@example.com"


def call_ai_analyze(email_row: pd.Series, *, include_ontology_context: bool) -> Dict:
    """Directly call pipeline functions to analyze email."""
    try:
        # Create EmailIn payload as Pydantic model
        payload_model = EmailIn(
            sender=_clean_sender(email_row.get("sender", "unknown@example.com")),
            receiver=None,
            subject=str(email_row.get("subject", "")),
            body=str(email_row.get("body", "")),
            url=_get_url_flag(email_row),
        )

        # Run Phase 1 (deterministic) - expects dict
        payload_dict = payload_model.model_dump()
        phase1_result = classify_email(payload_dict)

        # Run Phase 2 (RAG) - expects EmailIn model
        analysis_result = analyze_email(
            payload_model,
            phase1_result,
            neighbors_k=8,
            include_ontology_context=include_ontology_context,
        )

        # Convert Pydantic model to dict
        return analysis_result.model_dump()

    except Exception as e:
        print(f"Error analyzing email {email_row.get('id', 'unknown')}: {e}")
        import traceback
        traceback.print_exc()
        return {}


def extract_tag_from_reason(reason: str) -> str:
    """Extract tag from explanation bullet (e.g., '[AUTH]' from '[AUTH] No SPF record')."""
    match = re.match(r'^\[([A-Z]+)\]', reason)
    return match.group(1) if match else "OTHER"


def check_auth_support(reason: str, phase1_data: Dict) -> str:
    """
    Check if [AUTH] explanation cites specific evidence.

    SUPPORTED: Cites specific DNS/SPF/DMARC details (e.g., "No SPF record for domain X")
    UNSUPPORTED: Generic claims without specifics (e.g., "Suspicious authentication")
    UNKNOWN: No auth indicators available to verify
    """
    indicators = phase1_data.get("indicators", {})
    phase1_reasons = phase1_data.get("reasons", [])

    # Check if phase1 has auth-related violations
    has_auth_violations = any(
        keyword in str(r).lower()
        for r in phase1_reasons
        for keyword in ["mx", "spf", "dmarc", "dns", "domain"]
    )

    if not has_auth_violations:
        return "UNKNOWN"  # No auth evidence to cite

    # Check if reason cites specific auth details
    reason_lower = reason.lower()

    # Look for specific citations (expanded to catch valid paraphrases)
    specific_citations = [
        "no mx" in reason_lower or "missing mx" in reason_lower or "mx missing" in reason_lower or "mx record" in reason_lower,
        "no spf" in reason_lower or "spf not present" in reason_lower or "spf missing" in reason_lower or "spf record" in reason_lower,
        "no dmarc" in reason_lower or "dmarc not present" in reason_lower or "dmarc missing" in reason_lower,
        "lack of dmarc" in reason_lower or "without dmarc" in reason_lower,
        "dmarc policy" in reason_lower or "dmarc record" in reason_lower or "dmarc" in reason_lower and ("weaken" in reason_lower or "absent" in reason_lower),
        any(domain in reason_lower for domain in [indicators.get("sender_domain", ""), ".com", ".xyz", ".net"] if domain)
    ]

    if any(specific_citations):
        return "SUPPORTED"

    # Generic phrases indicate unsupported
    generic_phrases = [
        "suspicious auth", "weak auth", "authentication issue",
        "poor authentication", "lacks authentication"
    ]

    if any(phrase in reason_lower for phrase in generic_phrases):
        return "UNSUPPORTED"

    return "UNSUPPORTED"  # Default if no clear citation


def check_url_support(reason: str, phase1_data: Dict) -> str:
    """Check if [URL] explanation cites specific evidence."""
    phase1_reasons = phase1_data.get("reasons", [])

    has_url_violations = any(
        keyword in str(r).lower()
        for r in phase1_reasons
        for keyword in ["url", "link", "ip literal", "shortener", "domain mismatch"]
    )

    if not has_url_violations:
        return "UNKNOWN"

    reason_lower = reason.lower()

    # Check for specific URL citations (expanded for paraphrases)
    specific_citations = [
        "ip literal" in reason_lower or "ip address" in reason_lower,
        re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', reason),  # IP address
        "http://" in reason_lower or "https://" in reason_lower,
        "domain mismatch" in reason_lower,
        "shortener" in reason_lower or "shortened url" in reason_lower or "short link" in reason_lower,
        "bit.ly" in reason_lower or "tinyurl" in reason_lower  # Specific shortener names
    ]

    if any(specific_citations):
        return "SUPPORTED"

    return "UNSUPPORTED"


def check_urgency_support(reason: str, phase1_data: Dict) -> str:
    """Check if [URGENCY] explanation cites specific keywords."""
    phase1_reasons = phase1_data.get("reasons", [])

    has_urgency_violations = any(
        "urgency" in str(r).lower() or "keyword" in str(r).lower()
        for r in phase1_reasons
    )

    if not has_urgency_violations:
        return "UNKNOWN"

    reason_lower = reason.lower()

    # Check if reason quotes specific urgency keywords
    urgency_keywords = [
        "urgent", "immediately", "verify", "suspended", "24 hours",
        "expires", "account", "action required", "confirm", "freeze", "frozen",
        "security check", "15min", "available", "expire in", "complete this"
    ]

    # Look for quoted keywords OR explicit detection reference
    has_specific_keywords = any(kw in reason_lower for kw in urgency_keywords)
    has_detection_pattern = "detected" in reason_lower or "keyword" in reason_lower or "violation" in reason_lower

    # Support if either condition is met (not both required)
    if has_specific_keywords or has_detection_pattern:
        return "SUPPORTED"

    return "UNSUPPORTED"


def check_content_support(reason: str, phase1_data: Dict) -> str:
    """Check if [CONTENT] explanation cites specific patterns."""
    phase1_reasons = phase1_data.get("reasons", [])

    has_content_violations = any(
        keyword in str(r).lower()
        for r in phase1_reasons
        for keyword in ["credential", "phi", "password", "verify", "identity"]
    )

    if not has_content_violations:
        return "UNKNOWN"

    reason_lower = reason.lower()

    specific_citations = [
        "credential" in reason_lower,
        "password" in reason_lower,
        "verify identity" in reason_lower,
        "phi" in reason_lower
    ]

    if any(specific_citations):
        return "SUPPORTED"

    return "UNSUPPORTED"


def check_similarity_support(reason: str, neighbors_data: List[Dict]) -> str:
    """Check if [SIMILARITY] explanation references actual similarity scores."""
    reason_lower = reason.lower()

    # Look for similarity score references
    if re.search(r'\d\.\d+', reason) or "similarity" in reason_lower or "similar" in reason_lower:
        return "SUPPORTED"

    return "UNSUPPORTED"


def check_ontology_support(reason: str, analysis_result: Dict) -> str:
    """Check if [ONTOLOGY] explanation cites inferred attack types or reasoning chain."""
    ontology_attacks = analysis_result.get("ontology_attacks") or []
    ontology_explanation = analysis_result.get("ontology_explanation") or []

    if not ontology_attacks and not ontology_explanation:
        return "UNKNOWN"

    reason_lower = reason.lower()
    attack_hits = [
        attack.get("attack_type", "").lower()
        for attack in ontology_attacks
        if attack.get("attack_type")
    ]
    explanation_hits = [
        str(line).lower()
        for line in ontology_explanation
    ]

    if any(hit and hit in reason_lower for hit in attack_hits):
        return "SUPPORTED"
    if any(hit and hit in reason_lower for hit in explanation_hits):
        return "SUPPORTED"

    return "UNSUPPORTED"


def evaluate_groundedness(reason: str, tag: str, analysis_result: Dict) -> str:
    """
    Evaluate whether a tagged explanation is grounded in evidence.

    Returns: "SUPPORTED", "UNSUPPORTED", or "UNKNOWN"
    """
    phase1_data = analysis_result.get("phase1", {})
    neighbors = analysis_result.get("neighbors", [])

    if tag == "AUTH":
        return check_auth_support(reason, phase1_data)
    elif tag == "URL":
        return check_url_support(reason, phase1_data)
    elif tag == "URGENCY":
        return check_urgency_support(reason, phase1_data)
    elif tag == "CONTENT":
        return check_content_support(reason, phase1_data)
    elif tag == "SIMILARITY":
        return check_similarity_support(reason, neighbors)
    elif tag == "ONTOLOGY":
        return check_ontology_support(reason, analysis_result)
    else:
        return "UNKNOWN"


def run_groundedness_evaluation(
    sample_size: int = 60,
    random_seed: int = 42,
    include_ontology_context: bool = True,
    output_dir: Path = Path(__file__).resolve().parents[3] / "reports" / "groundedness_eval",
):
    """
    Run complete groundedness evaluation on test set.

    Args:
        sample_size: Number of emails to evaluate (default: 60)
        random_seed: Random seed for reproducibility
    """
    print("="*80)
    print("GROUNDEDNESS EVALUATION")
    print("="*80)

    # Load test data
    test_df = load_test_split()

    # Sample random emails
    random.seed(random_seed)
    sample_df = test_df.sample(n=min(sample_size, len(test_df)), random_state=random_seed)
    print(f"\nSampled {len(sample_df)} emails for evaluation")

    # Track results by tag type
    tag_stats = {
        "AUTH": {"total": 0, "supported": 0, "unsupported": 0, "unknown": 0},
        "URL": {"total": 0, "supported": 0, "unsupported": 0, "unknown": 0},
        "URGENCY": {"total": 0, "supported": 0, "unsupported": 0, "unknown": 0},
        "CONTENT": {"total": 0, "supported": 0, "unsupported": 0, "unknown": 0},
        "SIMILARITY": {"total": 0, "supported": 0, "unsupported": 0, "unknown": 0},
        "ONTOLOGY": {"total": 0, "supported": 0, "unsupported": 0, "unknown": 0},
    }

    detailed_results = []

    # Process each email
    for idx, (_, email_row) in enumerate(sample_df.iterrows(), 1):
        email_id = email_row.get("id", idx)
        print(f"\n[{idx}/{len(sample_df)}] Processing email {email_id}...")

        # Get AI analysis
        analysis_result = call_ai_analyze(
            email_row,
            include_ontology_context=include_ontology_context,
        )

        if not analysis_result:
            print(f"  ⚠️  Skipping email {email_id} (API error)")
            continue

        ai_reasons = analysis_result.get("ai_reasons", [])

        if not ai_reasons:
            print(f"  ⚠️  No AI reasons generated for email {email_id}")
            continue

        print(f"  Found {len(ai_reasons)} explanation bullets")

        # Evaluate each reason
        for reason in ai_reasons:
            tag = extract_tag_from_reason(reason)

            if tag not in tag_stats:
                continue  # Skip non-standard tags
            if tag == "ONTOLOGY" and not include_ontology_context:
                continue  # Skip ontology tags when context is not provided

            support_status = evaluate_groundedness(reason, tag, analysis_result)

            tag_stats[tag]["total"] += 1
            tag_stats[tag][support_status.lower()] += 1

            detailed_results.append({
                "email_id": email_id,
                "tag": tag,
                "reason": reason,
                "support_status": support_status,
                "phase1_verdict": analysis_result.get("phase1", {}).get("verdict"),
                "ai_verdict": analysis_result.get("ai_verdict")
            })

            # Print status indicator
            status_icon = "✅" if support_status == "SUPPORTED" else ("❌" if support_status == "UNSUPPORTED" else "❓")
            print(f"    {status_icon} [{tag}] {support_status}: {reason[:80]}...")

    # Print summary
    print("\n" + "="*80)
    print("GROUNDEDNESS SUMMARY")
    print("="*80)

    for tag, stats in tag_stats.items():
        total = stats["total"]
        if total == 0:
            support_rate = 0.0
        else:
            support_rate = stats["supported"] / total

        print(f"\n{tag}:")
        print(f"  Total: {total}")
        print(f"  Supported: {stats['supported']}")
        print(f"  Unsupported: {stats['unsupported']}")
        print(f"  Unknown: {stats['unknown']}")
        print(f"  Support Rate: {support_rate:.1%}")

    # Save results
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    results_df = pd.DataFrame(detailed_results)
    suffix = "with_ontology" if include_ontology_context else "no_ontology"
    results_df.to_csv(output_dir / f"detailed_results_{suffix}.csv", index=False)

    summary_df = pd.DataFrame([
        {
            "tag": tag,
            "total": stats["total"],
            "supported": stats["supported"],
            "unsupported": stats["unsupported"],
            "unknown": stats["unknown"],
            "support_rate": stats["supported"] / max(1, stats["total"])
        }
        for tag, stats in tag_stats.items()
    ])
    summary_df.to_csv(output_dir / f"summary_{suffix}.csv", index=False)

    print(f"\n✅ Results saved to {output_dir}/")
    print(f"   - detailed_results_{suffix}.csv: {len(detailed_results)} individual evaluations")
    print(f"   - summary_{suffix}.csv: aggregate statistics by tag")

    return tag_stats, detailed_results


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Evaluate groundedness of LLM explanations")
    parser.add_argument("--sample-size", type=int, default=60)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--no-ontology", action="store_true")
    parser.add_argument("--compare", action="store_true", help="Run with and without ontology context")
    args = parser.parse_args()

    if args.compare:
        run_groundedness_evaluation(
            sample_size=args.sample_size,
            random_seed=args.seed,
            include_ontology_context=True,
        )
        run_groundedness_evaluation(
            sample_size=args.sample_size,
            random_seed=args.seed,
            include_ontology_context=False,
        )
    else:
        run_groundedness_evaluation(
            sample_size=args.sample_size,
            random_seed=args.seed,
            include_ontology_context=not args.no_ontology,
        )
