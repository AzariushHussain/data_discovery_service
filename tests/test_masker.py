import pytest

from app.services.masker import mask_free_text, mask_value


@pytest.mark.parametrize(
    "phone",
    [
        "9876543210",
        "919876543210",
        "+919876543210",
        "09876543210",
        "+91 9876543210",
        "+91-98765-43210",
        "98765 43210",
    ],
)
def test_free_text_masks_entire_phone(phone):
    assert mask_free_text(f"Call ({phone}).", ["PHONE_IN"]) == "Call ([PHONE_REDACTED])."


@pytest.mark.parametrize(
    "token",
    ["abc919876543210xyz", "98765432101112", "XABCPK1234FY", "ABCEK1234F"],
)
def test_free_text_preserves_identifiers_and_invalid_pan(token):
    assert mask_free_text(token, ["PHONE_IN", "PAN"]) == token


def test_free_text_masks_phone_and_pan_together():
    assert mask_free_text(
        "Call +91 9876543210; PAN: ABCPK1234F.", ["PHONE_IN", "PAN"]
    ) == "Call [PHONE_REDACTED]; PAN: [PAN_REDACTED]."


def test_free_text_only_masks_requested_types():
    assert mask_free_text("ABCPK1234F 9876543210", []) == "ABCPK1234F 9876543210"


@pytest.mark.parametrize("email", ["a@example.com", "ab@example.com", "abc@example.com"])
def test_short_email_local_parts_are_always_masked(email):
    assert mask_value("EMAIL", email) != email
    assert "*" in mask_value("EMAIL", email).split("@")[0]


def test_email_masker_does_not_preserve_prose_as_a_domain():
    value = "Email c@example.com PAN ABCPK1234F"
    assert mask_value("EMAIL", value) == "[EMAIL_REDACTED]"
