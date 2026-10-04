import types

import pytest

from app.privacy import redactor
from app.privacy.boundary import sanitize_for_external

SUBJECT = "URGENT: confirm SSN 123-45-6789 for claim"
BODY = (
    "Dear customer at 42 Elm Street, verify your password at "
    "http://bit.ly/abc?uid=jsmith&t=99812 now. SSN 123-45-6789, phone 410-555-0123, "
    "DOB 03/14/1950, MRN 00482913, member ID AB12345, email john.smith@gmail.com, "
    "ZIP 21201, card 4111 1111 1111 1111. Visit https://paypa1-secure.com/login."
)
PATTERN_SENTINELS = [
    "123-45-6789", "410-555-0123", "03/14/1950", "00482913", "AB12345",
    "john.smith@gmail.com", "21201", "4111 1111", "uid=jsmith", "42 Elm Street",
]
SIGNALS = ["bit.ly/abc", "paypa1-secure.com/login", "gmail.com", "password", "URGENT"]


@pytest.fixture
def no_ner(monkeypatch):
    monkeypatch.setattr(redactor, "_NER", None)
    monkeypatch.setattr(redactor, "_NER_FAILED", True)


def test_patterns_remove_identifiers_and_keep_signals(no_ner):
    text, report = sanitize_for_external(SUBJECT, BODY)
    assert [s for s in PATTERN_SENTINELS if s in text] == []
    assert [s for s in SIGNALS if s not in text] == []
    assert report.ner_used is False
    assert report.version == redactor.REDACTOR_VERSION


def test_ner_masks_names(monkeypatch):
    fake = lambda chunk: [
        {"entity_group": "PER", "score": 0.99, "start": chunk.index("John"), "end": chunk.index("John") + 10}
    ] if "John Smith" in chunk else []
    monkeypatch.setattr(redactor, "_NER", fake)
    monkeypatch.setattr(redactor, "_NER_FAILED", False)
    text, report = sanitize_for_external("Hello", "Dear John Smith, your bill is due.")
    assert "John Smith" not in text and "[NAME]" in text
    assert report.ner_used is True


def test_analyze_email_sends_only_sanitized_text(no_ner, monkeypatch):
    from app.ai_service import service
    from app.pipeline.classify import classify_email
    from app.schemas import EmailIn

    outbound = []

    class Emb:
        def create(self, model, input):
            outbound.extend(input)
            return types.SimpleNamespace(data=[types.SimpleNamespace(embedding=[0.0] * 1536)])

    class Chat:
        def create(self, model, messages, **kw):
            outbound.extend(m["content"] for m in messages)
            return types.SimpleNamespace(choices=[types.SimpleNamespace(
                message=types.SimpleNamespace(content="[AUTH] test"))])

    client = types.SimpleNamespace(embeddings=Emb(), chat=types.SimpleNamespace(completions=Chat()))
    monkeypatch.setattr(service, "_build_ai_client", lambda prefer_deepseek=False: (client, "openai"))
    monkeypatch.setattr(service, "_nearest_neighbors", lambda vec, limit=8, include_benign=False: [])

    email = EmailIn(sender="a@example.com", subject=SUBJECT, body=BODY, url=1)
    phase1 = classify_email({**email.model_dump()} | {"sender": "a@example.com"})
    service.analyze_email(email, phase1)

    payload = "\n".join(outbound)
    assert payload, "no outbound call captured"
    assert [s for s in PATTERN_SENTINELS if s in payload] == []


@pytest.mark.parametrize("raw, expected", [
    ("http://jose@monkey.org=upgrade?x=1", "http://[USERINFO]@monkey.org=upgrade?[QUERY]"),
    ("see https://site.com/u/12345678/a", "see https://site.com/u/[ID]/a"),
    ("http://paypal.com@evil.ru/login", "http://[USERINFO]@evil.ru/login"),
    ("此電郵致 honeypot+yes@gmail.com若你", "此電郵致 [EMAIL]@gmail.com若你"),
    ("go http://bit.ly/abc now", "go http://bit.ly/abc now"),
])
def test_url_and_boundary_edge_cases(no_ner, raw, expected):
    assert redactor.redact_v2(raw)[0] == expected



# ---- v2.3 additions (gaps found by the planted-identifier audit, P1) ----

def test_v23_masks_bare_ipv4():
    from app.privacy.redactor import redact_v2
    out, _ = redact_v2("We saw a login from IP address 178.24.44.5 yesterday.", use_ner=False)
    assert "178.24.44.5" not in out and "[IP]" in out


def test_v23_keeps_ip_host_inside_url():
    from app.privacy.redactor import redact_v2
    out, _ = redact_v2("Verify at http://192.0.2.7/login now.", use_ner=False)
    assert "http://192.0.2.7/login" in out


def test_v23_does_not_mask_version_strings_with_large_octets():
    from app.privacy.redactor import redact_v2
    out, _ = redact_v2("Requires build 10.300.2.999 or later.", use_ner=False)
    assert "10.300.2.999" in out


def test_v23_masks_day_first_dates():
    from app.privacy.redactor import redact_v2
    out, _ = redact_v2("Date of birth: 14 March 1987.", use_ner=False)
    assert "1987" not in out and "[DATE]" in out


def test_v23_masks_circle_and_highway_addresses():
    from app.privacy.redactor import redact_v2
    for addr in ("5777 Riverside Circle", "9557 Hillcrest Highway"):
        out, _ = redact_v2(f"Please ship it to {addr} by Friday.", use_ner=False)
        assert addr.split()[0] not in out, out


def test_v23_masks_sentence_final_ipv4():
    from app.privacy.redactor import redact_v2
    for text in ("We saw a login from IP address 178.24.44.5.", "Noted: 249.84.13.161.", "(from 10.0.0.1)"):
        out, _ = redact_v2(text, use_ner=False)
        assert "[IP]" in out, out


def test_v23_keeps_longer_dotted_version_strings():
    from app.privacy.redactor import redact_v2
    out, _ = redact_v2("Upgrade to 1.2.3.4.5 today.", use_ner=False)
    assert "1.2.3.4.5" in out
