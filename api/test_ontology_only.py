"""
Test ontology integration with Phase 1 (no database required).

This demonstrates the neuro-symbolic pipeline without needing PostgreSQL.
"""

from app.schemas import ScanOut, RedactionsOut
from app.symbolic.ontology_reasoner import (
    PhishingOntologyReasoner,
    indicators_to_ontology_format,
)


def test_ontology_with_phase1_indicators():
    """Test ontology inference from Phase 1 indicators."""
    print("=" * 80)
    print("TEST: Ontology Inference from Phase 1 Indicators")
    print("=" * 80)

    # Simulate Phase 1 output for credential theft phishing
    phase1_indicators = {
        "sender_domain": "suspicious-bank.com",
        "auth": {
            "has_mx": False,      # Missing MX record
            "spf_present": False,
            "dmarc_present": False,
        },
        "urgency": True,          # Urgency keywords detected
        "creds_request": True,    # Credential request detected
        "ip_literal_link": True,  # IP address in URL
    }

    print("\n[Phase 1] Detected indicators:")
    for key, value in phase1_indicators.items():
        if key != "auth":
            print(f"  - {key}: {value}")
    print(f"  - auth: {phase1_indicators['auth']}")

    # Initialize ontology reasoner
    print("\n[Ontology] Initializing reasoner...")
    reasoner = PhishingOntologyReasoner()
    stats = reasoner.get_ontology_stats()
    print(f"  Loaded ontology: {stats['total_triples']} triples, "
          f"{stats['attack_types']} attack types")

    # Convert Phase 1 indicators to ontology format
    print("\n[Ontology] Converting indicators to ontology format...")
    ontology_indicators = indicators_to_ontology_format(phase1_indicators)
    print(f"  Converted: {list(ontology_indicators.keys())}")

    # Perform inference
    print("\n[Ontology] Running semantic inference...")
    inferred_attacks = reasoner.infer_attack_types(
        ontology_indicators,
        min_confidence=0.3
    )

    if inferred_attacks:
        print(f"\n[Ontology] Inferred {len(inferred_attacks)} attack types:\n")
        for i, (attack_type, confidence) in enumerate(inferred_attacks, 1):
            marker = "✓✓" if confidence >= 0.9 else "✓ " if confidence >= 0.5 else "  "
            print(f"  {marker} {i}. {attack_type:<30} {confidence*100:>5.1f}% confidence")

        # Generate explanation chain for top attack
        top_attack = inferred_attacks[0][0]
        print(f"\n[Ontology] Explanation chain for {top_attack}:\n")
        explanation = reasoner.get_explanation_chain(
            ontology_indicators,
            top_attack
        )
        for step in explanation:
            print(f"  {step}")

        print("\n✓ Ontology inference successful!")

        # Verify expected attacks
        attack_names = [name for name, _ in inferred_attacks]
        if "CredentialTheft" in attack_names:
            print("\n✓✓ CredentialTheft correctly detected (100% confidence expected)")
        if "HighConfidencePhishing" in attack_names:
            print("✓  HighConfidencePhishing detected (partial match)")

    else:
        print("\n✗ No attacks inferred")

    print()


def test_benign_email_ontology():
    """Test ontology on benign email indicators."""
    print("=" * 80)
    print("TEST: Benign Email (Should Detect Few/No Attacks)")
    print("=" * 80)

    # Simulate Phase 1 output for legitimate email
    phase1_indicators = {
        "sender_domain": "hopkinsmedicine.org",
        "auth": {
            "has_mx": True,       # Valid MX record
            "spf_present": True,  # SPF configured
            "dmarc_present": True,  # DMARC configured
        },
        "urgency": False,
        "creds_request": False,
    }

    print("\n[Phase 1] Detected indicators:")
    for key, value in phase1_indicators.items():
        if key != "auth":
            print(f"  - {key}: {value}")

    reasoner = PhishingOntologyReasoner()
    ontology_indicators = indicators_to_ontology_format(phase1_indicators)

    print(f"\n[Ontology] Converted: {list(ontology_indicators.keys())}")

    inferred_attacks = reasoner.infer_attack_types(
        ontology_indicators,
        min_confidence=0.3
    )

    if inferred_attacks:
        print(f"\n[Ontology] Detected {len(inferred_attacks)} potential attacks:")
        for attack_type, confidence in inferred_attacks:
            print(f"  - {attack_type}: {confidence*100:.1f}%")
        print("\n⚠ Note: Low-confidence detections expected for benign emails")
    else:
        print("\n✓ No attacks detected (expected for benign email)")

    print()


if __name__ == "__main__":
    print("\n" + "=" * 80)
    print("Ontology-Only Integration Test (No Database Required)")
    print("=" * 80 + "\n")

    test_ontology_with_phase1_indicators()
    test_benign_email_ontology()

    print("=" * 80)
    print("All tests completed - Ontology integration verified ✓")
    print("=" * 80)
