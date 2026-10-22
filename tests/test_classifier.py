import pytest

from app.services.classifier import PIIClassifier


@pytest.mark.parametrize("value", ["ABCPK1234F", "ABCFK1234F", "ABCTK1234F"])
def test_valid_pan(value):
    assert PIIClassifier._is_valid_pan(value)


@pytest.mark.parametrize("value", ["ABCEK1234F", "XABCPK1234F", "ABCPK1234F\n"])
def test_invalid_pan(value):
    assert not PIIClassifier._is_valid_pan(value)


@pytest.mark.parametrize("value", ["+91 9876543210", "919876543210", "98765-43210"])
def test_valid_phone(value):
    assert PIIClassifier._is_valid_phone(value)


@pytest.mark.parametrize("value", ["abc919876543210xyz", "98765432101112", "9999999999"])
def test_invalid_phone(value):
    assert not PIIClassifier._is_valid_phone(value)


@pytest.mark.parametrize("value", ["short", "123", "\u00b2" * 12])
def test_verhoeff_rejects_invalid_input(value):
    assert not PIIClassifier._validate_verhoeff(value)


@pytest.mark.parametrize("data_type", ["text", "varchar", "character varying", "VARCHAR(255)"])
def test_embedded_pii_in_arbitrarily_named_text_column(data_type):
    result = PIIClassifier.classify_column(
        "payload", data_type, ["Call +91 9876543210; PAN: ABCPK1234F."]
    )
    assert result["inferred_pii_type"] == "NONE"
    assert result["embedded_pii_types"] == ["PAN", "PHONE_IN"]
    assert result["risk_level"] == "CRITICAL"
    assert result["masked_evidence"] == ["Call [PHONE_REDACTED]; PAN: [PAN_REDACTED]."]


def test_at_sign_alone_is_not_email():
    result = PIIClassifier.classify_column("notes", "text", ["Meet @ noon"])
    assert result["embedded_pii_types"] == []


def test_phone_values_in_notes_are_classified():
    result = PIIClassifier.classify_column("notes", "text", ["9876543210"] * 20)
    assert result["inferred_pii_type"] == "PHONE_IN"
    assert result["embedded_pii_types"] == []


def test_junk_phone_column_is_not_classified():
    result = PIIClassifier.classify_column("phone", "text", ["N/A", "none", "0000000000"])
    assert result["inferred_pii_type"] == "NONE"


def test_unclassified_values_are_not_returned_as_evidence():
    result = PIIClassifier.classify_column("payload", "text", ["Sensitive unrecognized value"])
    assert result["masked_evidence"] == ["[UNCLASSIFIED_REDACTED]"]


@pytest.mark.parametrize(
    "name",
    [
        "Aarav Sharma", "Priya Nair", "Rohan Deshmukh", "Ananya Chatterjee",
        "Vikramjit Singh", "Sneha Iyer", "Karthik Reddy", "Meera Joshi",
        "Zoya Fernandes", "ANNE O'NEILL", "Jean-Luc Martin", "A. Sharma",
        "Dr. Asha Rao", "Jos\u00e9 Silva", "\u0906\u0930\u0935 \u0936\u0930\u094d\u092e\u093e",
    ],
)
def test_person_name_column_is_classified_and_masked(name):
    result = PIIClassifier.classify_column("full_name", "VARCHAR(120)", [name])
    assert result["inferred_pii_type"] == "FULL_NAME"
    assert result["risk_level"] == "MEDIUM"
    assert name not in result["masked_evidence"][0]


@pytest.mark.parametrize(
    "value",
    ["N/A", "Not Available", "Support Team", "Refund Pending", "Aarav",
     "call me tomorrow", "left at doorstep", "Call Me Tomorrow", "Left At Doorstep",
     "Aarav Sharma 123", "Call Aarav Sharma tomorrow.", "A B", "Anne--Marie Smith"],
)
def test_person_name_hint_does_not_classify_junk(value):
    result = PIIClassifier.classify_column("full_name", "text", [value])
    assert result["inferred_pii_type"] == "NONE"


@pytest.mark.parametrize(
    "column_name,value",
    [("city", "New Delhi"), ("company_name", "Acme Limited"),
     ("product_name", "Silver Anklets"), ("notes", "Refund Pending")],
)
def test_non_person_columns_are_not_names(column_name, value):
    result = PIIClassifier.classify_column(column_name, "text", [value])
    assert result["inferred_pii_type"] == "NONE"


@pytest.mark.parametrize("column_name", ["name", "buyer", "recipient", "author", "notes", "col_1"])
def test_names_are_detected_without_an_exact_person_column_name(column_name):
    result = PIIClassifier.classify_column(column_name, "text", ["Aarav Sharma"])
    assert result["inferred_pii_type"] == "FULL_NAME"


@pytest.mark.parametrize("name", ["Mr. Zoya Abidi", "Shri Zoya Abidi", "R. Abidi", "R Abidi"])
def test_name_signals_work_without_vocabulary_or_column_hint(name):
    result = PIIClassifier.classify_column("col_1", "text", [name])
    assert result["inferred_pii_type"] == "FULL_NAME"


def test_unfamiliar_names_in_person_columns_do_not_require_vocabulary():
    result = PIIClassifier.classify_column("full_name", "text", ["Zoya Abidi"])
    assert result["inferred_pii_type"] == "FULL_NAME"


def test_name_like_product_without_person_evidence_is_not_a_person():
    result = PIIClassifier.classify_column("product_name", "text", ["Maple Lantern"])
    assert result["inferred_pii_type"] == "NONE"


def test_classification_logs_counts_without_raw_values(caplog):
    with caplog.at_level("INFO", logger="app.services.classifier"):
        PIIClassifier.classify_column("full_name", "text", ["Aarav Sharma"])
        PIIClassifier.classify_column("empty", "text", [])
    assert "Classifying column=full_name sample_count=1" in caplog.text
    assert "Classifying column=empty sample_count=0" in caplog.text
    assert "Aarav Sharma" not in caplog.text


@pytest.mark.parametrize(
    "address",
    [
        "Flat 302, Green Glen Layout, Bellandur, Bengaluru, Karnataka",
        "House No 14, 2nd Cross, HSR Layout Sector 2, Bengaluru",
        "Plot 88, Baner Pashan Link Road, Near Savitribai Phule Chowk, Pune",
        "12B Ballygunge Circular Road, Flat 4A, Kolkata, West Bengal",
        "B-42, Lajpat Nagar Part II, Ring Road, New Delhi",
        "No 27, TTK Road, Alwarpet, Near Music Academy, Chennai",
        "Plot 401, Road No 36, Jubilee Hills, Hyderabad, Telangana",
        "704 Sea Breeze Tower, Gokhale Road, Dadar West, Mumbai",
        "Green Glen Layout, Near Main Road, Bengaluru",
    ],
)
def test_postal_addresses_are_classified_and_redacted(address):
    result = PIIClassifier.classify_column("residential_address", "TEXT", [address])
    assert result["inferred_pii_type"] == "POSTAL_ADDRESS"
    assert result["risk_level"] == "HIGH"
    assert result["masked_evidence"] == ["[ADDRESS_REDACTED]"]


def test_address_values_can_be_found_without_address_column_name():
    result = PIIClassifier.classify_column(
        "notes", "varchar", ["Flat 18, Maple Road, Sector 7, Pune"]
    )
    assert result["inferred_pii_type"] == "POSTAL_ADDRESS"


@pytest.mark.parametrize(
    "value",
    [
        "N/A", "Unknown", "New Delhi", "560103",
        "Road Road Road Road Road", "Sector Road",
        "Please update my Flat 302 address near Main Road.",
        "Call 9876543210 about the refund for Flat 302, Main Road.",
        "Road trip through Sector 2 was enjoyable today.",
    ],
)
def test_junk_and_prose_are_not_postal_addresses(value):
    assert not PIIClassifier._is_valid_postal_address(value, "notes")


def test_address_metadata_alone_cannot_classify_a_city():
    result = PIIClassifier.classify_column("residential_address", "text", ["Bengaluru"])
    assert result["inferred_pii_type"] == "NONE"


def test_perfect_small_sample_has_full_match_ratio_and_weighted_score():
    result = PIIClassifier.classify_column("phone", "text", ["9876543210"] * 8)
    assert result["match_ratio"] == 1.0
    assert result["confidence"] == 0.4
    assert result["embedded_match_ratio"] == 0.0
    assert result["embedded_confidence"] == 0.0


def test_embedded_scores_count_each_row_once_across_multiple_types():
    result = PIIClassifier.classify_column(
        "body", "text",
        ["Call 9876543210; PAN: ABCPK1234F.", "No personal information here."],
    )
    assert result["inferred_pii_type"] == "NONE"
    assert result["confidence"] == 0.0
    assert result["match_ratio"] == 0.0
    assert result["embedded_match_ratio"] == 0.5
    assert result["embedded_confidence"] == 0.05
    assert result["embedded_pii_types"] == ["PAN", "PHONE_IN"]
    assert "1/2 sampled rows" in result["justification"]


def test_mixed_column_keeps_primary_and_embedded_evidence_separate():
    result = PIIClassifier.classify_column(
        "notes", "text", ["9876543210", "9845012345", "Call 9123456789 tomorrow."]
    )
    assert result["inferred_pii_type"] == "PHONE_IN"
    assert result["match_ratio"] == pytest.approx(2 / 3, abs=0.0001)
    assert result["embedded_match_ratio"] == pytest.approx(1 / 3, abs=0.0001)
    assert result["confidence"] == 0.1
    assert result["embedded_confidence"] == 0.05


def test_no_samples_have_no_detection_support():
    result = PIIClassifier.classify_column("phone", "text", [])
    for key in ("confidence", "match_ratio", "embedded_match_ratio", "embedded_confidence"):
        assert result[key] == 0.0


def test_rejected_embedded_candidates_do_not_increase_scores():
    result = PIIClassifier.classify_column(
        "body", "text", ["Call 9999999999; PAN: ABCEK1234F; ref abc919876543210xyz"]
    )
    assert result["embedded_match_ratio"] == 0.0
    assert result["embedded_confidence"] == 0.0


def test_email_primary_column_does_not_expose_pan_in_mixed_prose():
    samples = ["a@example.com", "b@example.com", "Email c@example.com PAN ABCPK1234F"]
    result = PIIClassifier.classify_column("notes", "text", samples)
    assert result["inferred_pii_type"] == "EMAIL"
    assert result["embedded_pii_types"] == ["EMAIL", "PAN"]
    assert result["masked_evidence"][2] == "[MIXED_CONTENT_REDACTED]"
    for raw in ("a@example.com", "b@example.com", "c@example.com", "ABCPK1234F"):
        assert all(raw not in evidence for evidence in result["masked_evidence"])


def test_minority_standalone_pii_is_masked_by_its_own_type():
    result = PIIClassifier.classify_column(
        "notes", "text", ["a@example.com", "b@example.com", "ABCPK1234F"]
    )
    assert result["inferred_pii_type"] == "EMAIL"
    assert result["masked_evidence"][2] == "ABC******F"


def test_email_domains_cannot_expose_other_identifiers_in_evidence():
    result = PIIClassifier.classify_column(
        "email", "text", ["contact@ABCPK1234F.example", "contact@9876543210.example"]
    )
    for evidence in result["masked_evidence"]:
        assert "ABCPK1234F" not in evidence
        assert "9876543210" not in evidence


@pytest.mark.parametrize(
    "primary,column_name",
    [("a@example.com", "full_name"), ("9876543210", "full_name"),
     ("ABCPK1234F", "full_name"), ("Aarav Sharma", "full_name"),
     ("Flat 18, Maple Road, Sector 7, Pune", "full_name"),
     ("1992-04-15", "date_of_birth"), ("560103", "full_name")],
)
def test_mixed_prose_is_not_exposed_under_any_primary_mask(primary, column_name):
    prose = "Aarav Sharma lives at Flat 18, Maple Road. PAN ABCPK1234F; email c@example.com"
    result = PIIClassifier.classify_column(column_name, "text", [primary, primary, prose])
    assert result["inferred_pii_type"] != "NONE"
    assert result["masked_evidence"][2] == "[MIXED_CONTENT_REDACTED]"


def test_minority_phone_is_masked_even_below_column_threshold():
    result = PIIClassifier.classify_column("notes", "text", ["9876543210"] + ["N/A"] * 4)
    assert result["inferred_pii_type"] == "NONE"
    assert result["masked_evidence"][0] == "+91-******3210"


@pytest.mark.parametrize("identifier", ["ABCPK1234F", "234567890124"])
def test_minority_government_identifier_sets_critical_risk(identifier):
    result = PIIClassifier.classify_column(
        "notes", "text", ["a@example.com", "b@example.com", identifier]
    )
    assert result["inferred_pii_type"] == "EMAIL"
    assert result["embedded_pii_types"] == []
    assert result["risk_level"] == "CRITICAL"


@pytest.mark.parametrize("value,expected_type,risk", [
    ("ABCPK1234F", "PAN", "CRITICAL"),
    ("9876543210", "PHONE_IN", "HIGH"),
    ("Aarav Sharma", "FULL_NAME", "MEDIUM"),
    ("560001", "PINCODE", "LOW"),
])
def test_standalone_hits_below_primary_threshold_still_set_risk(value, expected_type, risk):
    result = PIIClassifier.classify_column("notes", "text", [value] + ["N/A"] * 4)
    assert result["inferred_pii_type"] == "NONE"
    assert result["match_ratio"] == 0.0
    assert result["confidence"] == 0.0
    assert result["embedded_pii_types"] == []
    assert result["risk_level"] == risk
    assert expected_type in result["justification"]


def test_junk_only_column_has_no_risk():
    result = PIIClassifier.classify_column("notes", "text", ["N/A", "???"])
    assert result["risk_level"] == "NONE"


@pytest.mark.parametrize("value", ["2020-01-15", "15-01-2020", "15/01/2020", "2020/01/15"])
def test_child_birth_dates_are_classified_and_fully_masked(value):
    result = PIIClassifier.classify_column("date_of_birth", "DATE", [value])
    assert result["inferred_pii_type"] == "DOB"
    assert result["risk_level"] == "HIGH"
    assert result["masked_evidence"] == ["****-**-**"]


@pytest.mark.parametrize("column_name", [
    "dob", "DOB", "date_of_birth", "birth_date", "birthdate", "birthday",
    "customer_dob", "customerDOB", "dateOfBirth", "dateofbirth",
])
def test_birth_context_supports_common_column_names(column_name):
    result = PIIClassifier.classify_column(column_name, "TEXT", ["2000-02-29"])
    assert result["inferred_pii_type"] == "DOB"


@pytest.mark.parametrize("column_name", ["order_date", "created_at", "last_updated", "payment_date", "invoiceDate"])
def test_known_transaction_dates_are_not_dob(column_name):
    result = PIIClassifier.classify_column(column_name, "DATE", ["2000-01-01"])
    assert result["inferred_pii_type"] == "NONE"
    assert result["risk_level"] == "NONE"
    assert result["masked_evidence"] == ["[UNCLASSIFIED_REDACTED]"]


@pytest.mark.parametrize("column_name", ["notes", "field_1", "col_x"])
@pytest.mark.parametrize("data_type", ["TEXT", "DATE"])
def test_dob_candidates_do_not_require_a_birth_column_name(column_name, data_type):
    result = PIIClassifier.classify_column(column_name, data_type, ["2020-01-15"])
    assert result["inferred_pii_type"] == "DOB"
    assert result["risk_level"] == "HIGH"
    assert result["masked_evidence"] == ["****-**-**"]


@pytest.mark.parametrize("value", [
    "2000-01-01 arbitrary trailing text", "2000-01-01 12:00:00", "2000-01-01T00:00:00Z",
    "Please verify 2000-01-01", "2023-02-29", "2020-13-01", "N/A", "9999-01-01",
])
def test_birth_hint_does_not_override_invalid_or_nonstandalone_dates(value):
    result = PIIClassifier.classify_column("dob", "TEXT", [value])
    assert result["inferred_pii_type"] == "NONE"
    assert "DOB" not in result["justification"]


def test_birth_date_today_is_valid_but_tomorrow_is_not():
    from datetime import date, timedelta

    today = date.today()
    assert PIIClassifier._is_valid_dob(today.isoformat(), "dob")
    assert not PIIClassifier._is_valid_dob((today + timedelta(days=1)).isoformat(), "dob")


@pytest.mark.parametrize("column_name", [
    "residential_pincode", "residentialPincode", "country_pincode",
    "account_pincode", "pincode", "notes", "field_1",
])
def test_pincode_guard_does_not_reject_partial_word_matches(column_name):
    result = PIIClassifier.classify_column(column_name, "TEXT", ["560001"])
    assert result["inferred_pii_type"] == "PINCODE"
    assert result["risk_level"] == "LOW"
    assert result["masked_evidence"] == ["56****"]


@pytest.mark.parametrize("column_name", [
    "id", "customer_id", "customerId", "customerID", "invoice_number", "invoiceNumber",
    "order_amount", "unit_price", "item_count", "order_total", "CUSTOMER_ID",
])
def test_pincode_guard_rejects_identifier_and_money_tokens(column_name):
    result = PIIClassifier.classify_column(column_name, "INTEGER", ["560001"])
    assert result["inferred_pii_type"] == "NONE"
    assert result["risk_level"] == "NONE"


@pytest.mark.parametrize("value", ["012345", "912345", "5600012", "56000", "abc", "Bengaluru 560001"])
def test_pincode_name_does_not_override_invalid_values(value):
    result = PIIClassifier.classify_column("pincode", "TEXT", [value])
    assert result["inferred_pii_type"] == "NONE"
