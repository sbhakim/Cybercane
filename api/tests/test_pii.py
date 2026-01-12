from app.pipeline.pii import redact


def test_redact_counts_and_masks():
    text = (
        "Contact me at john.doe@example.com or 555-123-4567. "
        "SSN 123-45-6789. CC 4111 1111 1111 1111. DOB 01/02/1980."
    )

    redacted, counts = redact(text)

    # Counts by type
    assert counts["email"] == 1
    assert counts["phone"] == 1
    assert counts["ssn"] == 1
    assert counts["cc"] == 1
    assert counts["dob"] == 1
    assert sum(counts.values()) == 5

    # Ensure PII is masked and original values are gone
    assert "john.doe@example.com" not in redacted
    assert "@example.com" in redacted
    assert "123-45-6789" not in redacted
    assert "4111 1111 1111 1111" not in redacted
    assert "01/02/1980" not in redacted
    assert "**/**/****" in redacted


