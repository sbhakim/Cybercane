"""
Challenge set for the evidence-based groundedness checker.

WRONG: plausible-looking explanations that contradict or invent evidence;
none may be judged SUPPORTED. RIGHT: faithful explanations; all must be SUPPORTED.
"""

import pytest

from app.evaluation import groundedness as v1
from app.evaluation.groundedness_v2 import evaluate_groundedness_v2

EVIDENCE = {
    "phase1": {
        "indicators": {
            "sender_domain": "medstar-health.org", "has_mx": True, "spf_present": False,
            "dmarc_present": False, "dmarc_policy": "none", "link_hosts": ["bit.ly"],
            "shortened_url": True, "urgency": True, "creds_request": True,
        },
        "redacted_body": "Your account will be suspended. Verify your password within 24 hours at http://bit.ly/abc",
    },
    "neighbors": [{"similarity": 0.82}, {"similarity": 0.71}, {"similarity": 0.64}],
    "ontology_attacks": [{"attack_type": "UrgentCredentialRequest", "confidence": 1.0}],
    "ontology_suggestions": [{"attack_type": "CredentialTheft", "coverage": 0.5, "missing": ["hasMissingMX"]}],
}
NO_NEIGHBORS = {**EVIDENCE, "neighbors": []}

WRONG = [
    ("SIMILARITY", "High similarity (0.99) to known phishing", EVIDENCE),
    ("SIMILARITY", "Top neighbor similarity 0.91 indicates a known campaign", EVIDENCE),
    ("SIMILARITY", "Similar to known phishing (0.82)", NO_NEIGHBORS),
    ("SIMILARITY", "Average similarity 0.45 across neighbors", EVIDENCE),
    ("SIMILARITY", "Matches phishing corpus at 0.30 similarity", EVIDENCE),
    ("ONTOLOGY", "Classified as CredentialTheft by the ontology", EVIDENCE),        # only suggested
    ("ONTOLOGY", "Ontology infers Prescription Fraud", EVIDENCE),                   # not asserted
    ("ONTOLOGY", "Matches AppointmentScam pattern", EVIDENCE),
    ("ONTOLOGY", "HighConfidencePhishing rule satisfied", EVIDENCE),
    ("ONTOLOGY", "Insurance Verification Phish detected", EVIDENCE),
    ("AUTH", "Missing MX record for sender domain", EVIDENCE),                      # MX present
    ("AUTH", "No MX record found", EVIDENCE),
    ("AUTH", "DMARC policy is reject", EVIDENCE),                                   # policy none
    ("AUTH", "DMARC policy p=quarantine", EVIDENCE),
    ("AUTH", "Sender lacks MX and SPF records", EVIDENCE),                          # MX present
    ("URL", "IP literal link 185.234.123.45 detected", EVIDENCE),
    ("URL", "Link uses an IP address instead of a domain", EVIDENCE),
    ("URL", "Link points to paypa1-secure.com", EVIDENCE),                          # host not in links
    ("URL", "Domain mismatch between sender and link", EVIDENCE),
    ("URL", "Lookalike domain in the link", EVIDENCE),
    ("URL", "Link to evil-login.ru detected", EVIDENCE),
    ("URGENCY", "Uses the phrase 'act now or lose access'", EVIDENCE),              # not in body
    ("URGENCY", "Keyword 'final notice' detected", EVIDENCE),
    ("URGENCY", "Urgency keyword 'immediately' present", EVIDENCE),
    ("URGENCY", "Threatens with 'legal action'", EVIDENCE),
    ("CONTENT", "Requests login credentials", {**EVIDENCE, "phase1": {**EVIDENCE["phase1"], "indicators": {
        **EVIDENCE["phase1"]["indicators"], "creds_request": False}}}),
    ("CONTENT", "Asks for the password", {**EVIDENCE, "phase1": {**EVIDENCE["phase1"], "indicators": {
        **EVIDENCE["phase1"]["indicators"], "creds_request": False}}}),
    ("URGENCY", "Urgent tone detected", {**EVIDENCE, "phase1": {**EVIDENCE["phase1"], "indicators": {
        **EVIDENCE["phase1"]["indicators"], "urgency": False}}}),
    ("AUTH", "No SPF record", {**EVIDENCE, "phase1": {**EVIDENCE["phase1"], "indicators": {
        **EVIDENCE["phase1"]["indicators"], "spf_present": True}}}),
    ("URL", "Shortened URL (bit.ly) detected", {**EVIDENCE, "phase1": {**EVIDENCE["phase1"], "indicators": {
        **EVIDENCE["phase1"]["indicators"], "shortened_url": False, "link_hosts": []}}}),
]

RIGHT = [
    ("SIMILARITY", "High similarity (0.82) to known phishing", EVIDENCE),
    ("SIMILARITY", "Average of top-3 similarity is 0.72", EVIDENCE),
    ("ONTOLOGY", "Ontology asserts UrgentCredentialRequest", EVIDENCE),
    ("AUTH", "No SPF record and no DMARC record for the sender domain", EVIDENCE),
    ("AUTH", "DMARC policy is none", EVIDENCE),
    ("URL", "Shortened URL (bit.ly) detected", EVIDENCE),
    ("URGENCY", "Urgency keyword 'suspended' detected", EVIDENCE),
    ("URGENCY", "Mentions '24 hours' deadline", EVIDENCE),
    ("CONTENT", "Requests the account password", EVIDENCE),
]


def test_challenge_set_has_thirty_wrong_cases():
    assert len(WRONG) == 30


@pytest.mark.parametrize("tag, reason, ev", WRONG)
def test_wrong_explanations_are_never_supported(tag, reason, ev):
    assert evaluate_groundedness_v2(reason, tag, ev) != "SUPPORTED"


@pytest.mark.parametrize("tag, reason, ev", RIGHT)
def test_faithful_explanations_are_supported(tag, reason, ev):
    assert evaluate_groundedness_v2(reason, tag, ev) == "SUPPORTED"


def test_v1_checker_accepts_every_invented_similarity_claim():
    """
    Documents why the v1 SIMILARITY support rate (100%) is not evidence: v1
    accepts any bullet containing "similar" or a decimal, including one made
    when no neighbor was retrieved at all.
    """
    sim_wrong = [(t, r, ev) for t, r, ev in WRONG if t == "SIMILARITY"]
    assert all(v1.evaluate_groundedness(r, t, ev) == "SUPPORTED" for t, r, ev in sim_wrong)
    assert all(evaluate_groundedness_v2(r, t, ev) != "SUPPORTED" for t, r, ev in sim_wrong)
