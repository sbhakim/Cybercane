"""
Quick test to verify ontology integration with RAG pipeline.

Tests the full neuro-symbolic pipeline:
Phase 1 (Rules) → Ontology (Reasoning) → Phase 2 (RAG)
"""

from app.schemas import EmailIn, ScanOut, RedactionsOut
from app.pipeline.classify import classify_email
from app.ai_service.service import analyze_email


def test_credential_theft_detection():
    """Test ontology detection of credential theft phishing."""
    print("=" * 80)
    print("TEST: Credential Theft Detection with Ontology")
    print("=" * 80)

    # Simulate credential theft email
    email = {
        "sender": "security@suspicious-bank.com",
        "receiver": "patient@hospital.org",
        "subject": "URGENT: Verify Your Account",
        "body": "Your account will be locked. Please verify your password immediately at http://198.45.123.67/login",
        "url": 1
    }

    # Phase 1: Deterministic analysis
    print("\n[Phase 1] Running deterministic rules...")
    phase1_result = classify_email(email)

    print(f"  Verdict: {phase1_result.verdict}")
    print(f"  Score: {phase1_result.score}")
    print(f"  Indicators: {list(phase1_result.indicators.keys())[:5]}...")

    # Phase 2: RAG + Ontology
    print("\n[Phase 2] Running ontology + RAG analysis...")

    try:
        email_in = EmailIn(**email)
        ai_result = analyze_email(email_in, phase1_result, neighbors_k=5)

        print(f"  AI Verdict: {ai_result.ai_verdict}")
        print(f"  AI Score: {ai_result.ai_score}")

        # Check ontology results
        if ai_result.ontology_attacks:
            print(f"\n[Ontology] Inferred {len(ai_result.ontology_attacks)} attack types:")
            for attack in ai_result.ontology_attacks[:5]:
                print(f"  - {attack.attack_type}: {attack.confidence*100:.1f}% confidence")

            if ai_result.ontology_explanation:
                print(f"\n[Ontology] Reasoning chain:")
                for step in ai_result.ontology_explanation:
                    print(f"  {step}")
        else:
            print("\n[Ontology] No attacks inferred (ontology may not be available)")

        print("\n✓ Test completed successfully")

    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()


def test_benign_email():
    """Test ontology on legitimate email."""
    print("\n" + "=" * 80)
    print("TEST: Benign Email (No Ontology Attacks)")
    print("=" * 80)

    email = {
        "sender": "appointments@hopkinsmedicine.org",
        "receiver": "patient@hospital.org",
        "subject": "Appointment Reminder",
        "body": "This is a reminder of your appointment on Monday at 2pm with Dr. Smith.",
        "url": 0
    }

    print("\n[Phase 1] Running deterministic rules...")
    phase1_result = classify_email(email)
    print(f"  Verdict: {phase1_result.verdict}")

    try:
        email_in = EmailIn(**email)
        ai_result = analyze_email(email_in, phase1_result)

        print(f"\n[Phase 2] AI Verdict: {ai_result.ai_verdict}")

        if ai_result.ontology_attacks:
            print(f"[Ontology] Detected {len(ai_result.ontology_attacks)} potential attacks (false positive?)")
            for attack in ai_result.ontology_attacks[:3]:
                print(f"  - {attack.attack_type}: {attack.confidence*100:.1f}%")
        else:
            print("[Ontology] No attacks detected ✓")

        print("\n✓ Test completed")

    except Exception as e:
        print(f"\n✗ Test failed: {e}")


if __name__ == "__main__":
    print("\n" + "=" * 80)
    print("Ontology Integration Test Suite")
    print("=" * 80 + "\n")

    test_credential_theft_detection()
    test_benign_email()

    print("\n" + "=" * 80)
    print("All tests completed")
    print("=" * 80)
