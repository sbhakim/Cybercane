"""
Quick test script to validate ontology loading and basic inference.

Run with: python -m app.symbolic.test_ontology
"""

from app.symbolic.ontology_reasoner import PhishingOntologyReasoner, indicators_to_ontology_format


def test_ontology_loading():
    """Test 1: Verify ontology loads successfully."""
    print("=" * 80)
    print("TEST 1: Ontology Loading")
    print("=" * 80)

    reasoner = PhishingOntologyReasoner()
    stats = reasoner.get_ontology_stats()

    print(f"✓ Ontology loaded successfully")
    print(f"  - Total triples: {stats['total_triples']}")
    print(f"  - Attack types: {stats['attack_types']}")
    print(f"  - Classes: {stats['classes']}")
    print(f"  - Properties: {stats['properties']}")
    print()


def test_credential_theft_inference():
    """Test 2: Infer CredentialTheft from indicators."""
    print("=" * 80)
    print("TEST 2: CredentialTheft Inference")
    print("=" * 80)

    reasoner = PhishingOntologyReasoner()

    # Simulate Phase 1 indicators for credential theft attack
    indicators = {
        "creds_request": True,
        "missing_mx": True,
        "urgency": True,
    }

    results = reasoner.infer_attack_types(indicators)

    print(f"Input indicators: {list(indicators.keys())}")
    print(f"\nInferred attack types:")
    for attack_type, confidence in results:
        print(f"  - {attack_type}: {confidence*100:.1f}% confidence")

    # Verify CredentialTheft is detected
    if any(name == "CredentialTheft" for name, _ in results):
        print("\n✓ CredentialTheft correctly inferred")
    else:
        print("\n✗ WARNING: CredentialTheft not detected")

    print()


def test_explanation_chain():
    """Test 3: Generate explanation chain."""
    print("=" * 80)
    print("TEST 3: Explanation Chain Generation")
    print("=" * 80)

    reasoner = PhishingOntologyReasoner()

    indicators = {
        "creds_request": True,
        "missing_mx": True,
    }

    # Get inferred attack types
    results = reasoner.infer_attack_types(indicators)

    if results:
        attack_type = results[0][0]  # Top result
        explanations = reasoner.get_explanation_chain(indicators, attack_type)

        print(f"Explanation chain for {attack_type}:\n")
        for i, exp in enumerate(explanations, 1):
            print(f"{i}. {exp}")
    else:
        print("✗ No attack types inferred")

    print()


def test_url_based_attack():
    """Test 4: URL-based attack detection."""
    print("=" * 80)
    print("TEST 4: URL-Based Attack Detection")
    print("=" * 80)

    reasoner = PhishingOntologyReasoner()

    indicators = {
        "ip_literal_link": True,
        "domain_mismatch": True,
        "shortened_url": False,
    }

    results = reasoner.infer_attack_types(indicators, min_confidence=0.5)

    print(f"Input indicators: {list(indicators.keys())}")
    print(f"\nInferred attack types:")

    if results:
        for attack_type, confidence in results:
            print(f"  - {attack_type}: {confidence*100:.1f}% confidence")
    else:
        print("  (No attacks detected at 50% confidence threshold)")

    print()


def test_indicator_conversion():
    """Test 5: Phase 1 indicator conversion."""
    print("=" * 80)
    print("TEST 5: Phase 1 Indicator Conversion")
    print("=" * 80)

    # Simulate Phase 1 indicators dictionary
    phase1_indicators = {
        "auth": {
            "has_mx": False,
            "spf_present": False,
            "dmarc_present": True,
        },
        "urgency": True,
        "creds_request": True,
        "ip_literal_link": True,
    }

    converted = indicators_to_ontology_format(phase1_indicators)

    print("Phase 1 indicators:")
    print(f"  {phase1_indicators}")
    print("\nConverted to ontology format:")
    print(f"  {converted}")
    print()


def main():
    """Run all tests."""
    print("\n" + "=" * 80)
    print("PhishOnt Ontology Reasoner Test Suite")
    print("=" * 80 + "\n")

    try:
        test_ontology_loading()
        test_credential_theft_inference()
        test_explanation_chain()
        test_url_based_attack()
        test_indicator_conversion()

        print("=" * 80)
        print("✓ ALL TESTS COMPLETE
        print("=" * 80)

    except Exception as e:
        print(f"\n✗ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
