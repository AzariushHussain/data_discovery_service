from datetime import date, datetime
import logging
import re
import unicodedata
from typing import Any
from app.services.masker import (
    EMAIL_PATTERN,
    PAN_IN_TEXT,
    PAN_PATTERN,
    PHONE_IN_TEXT,
    PHONE_PATTERN,
    mask_free_text,
    mask_value,
)
from app.services.risk import calculate_confidence, determine_risk_level

logger = logging.getLogger(__name__)


class PIIClassifier:
    """Performs two-stage value and column-name classification for Indian PII."""

    _NAME_COLUMN_HINTS = {
        "name", "full_name", "fullname", "customer_name", "person_name",
        "contact_name", "employee_name", "patient_name", "account_holder_name",
        "customer", "person", "buyer", "recipient", "author", "applicant", "beneficiary",
    }
    # A limited value signal for generic columns, not a comprehensive name registry.
    _NAME_TOKENS = {
        "sharma", "nair", "deshmukh", "chatterjee", "singh", "iyer", "reddy",
        "joshi", "kumar", "patel", "gupta", "verma", "rao", "das", "khan",
        "hussain", "ali", "kaur", "shah", "menon", "pillai", "fernandes",
    }

    # Verhoeff Checksum Arrays for Aadhaar Validation
    _VERHOEFF_D = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
        [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
        [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
        [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
        [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
    ]
    _VERHOEFF_P = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
        [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
        [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
        [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
    ]
    _VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]

    @classmethod
    def _validate_verhoeff(cls, number_str: str) -> bool:
        """Validates a 12-digit string using the Verhoeff checksum algorithm."""
        if not re.fullmatch(r"[0-9]{12}", number_str):
            return False
        c = 0
        length = len(number_str)
        for i in range(length):
            digit = int(number_str[length - i - 1])
            c = cls._VERHOEFF_D[c][cls._VERHOEFF_P[(i % 8)][digit]]
        return c == 0

    @classmethod
    def _is_valid_pan(cls, val: str) -> bool:
        # Format: ABCPF1234F (4th char must be entity code like P, C, H, F, A, T, B, L, J, G)
        return bool(re.fullmatch(PAN_PATTERN, val))

    @classmethod
    def _is_valid_phone(cls, val: str) -> bool:
        if not re.fullmatch(PHONE_PATTERN, val):
            return False
        digits = re.sub(r"\D", "", val)
        return len(set(digits[-10:])) > 1

    @classmethod
    def _is_valid_pincode(cls, val: str) -> bool:
        # 6-digit Indian postal code starting with 1-8
        return bool(re.match(r"^[1-8]\d{5}$", val))

    @classmethod
    def _is_valid_email(cls, val: str) -> bool:
        return bool(re.fullmatch(EMAIL_PATTERN, val))

    @classmethod
    def _is_valid_dob(cls, val: str, column_name: str) -> bool:
        # Known transaction metadata reduces false positives; generic names remain eligible.
        name = re.sub(r"([a-z])([A-Z])", r"\1_\2", column_name).lower()
        if name in {
            "order_date", "payment_date", "invoice_date", "transaction_date",
            "created_at", "updated_at", "last_updated",
        }:
            return False
        for fmt in ("%Y-%m-%d", "%d-%m-%Y", "%d/%m/%Y", "%Y/%m/%d"):
            try:
                parsed = datetime.strptime(val, fmt).date()
                if parsed <= date.today():
                    return True
            except ValueError:
                continue
        return False

    @classmethod
    def _is_valid_full_name(cls, val: str, column_name: str) -> bool:
        """Combine name-shaped values with metadata or explicit name signals."""
        val = val.strip()
        if not 3 <= len(val) <= 100:
            return False

        words = val.split()
        has_honorific = bool(
            words and words[0].lower().rstrip(".") in {"mr", "mrs", "ms", "dr", "shri", "smt"}
        )
        if has_honorific:
            words = words[1:]
        if not 2 <= len(words) <= 4:
            return False

        has_initial = False
        for word in words:
            if word.lower().rstrip(".") in {
                "unknown", "none", "null", "not", "available", "provided",
                "pending", "shipped", "delivered", "cancelled", "processing",
                "refund", "support", "team", "call", "me", "tomorrow", "left",
                "at", "doorstep", "please", "order", "invoice", "payment",
                "new", "delhi", "road", "nagar", "layout", "limited", "ltd",
            }:
                return False
            # Reject lowercase prose while preserving scripts that have no letter case.
            if word[0].islower():
                return False
            if len(word) == 2 and word[0].isalpha() and word[1] == ".":
                has_initial = True
                continue
            for part in re.split(r"[-'\u2019]", word):
                if not any(char.isalpha() for char in part) or not all(
                    char.isalpha() or unicodedata.category(char).startswith("M")
                    for char in part
                ):
                    return False
            has_initial = has_initial or len(word) == 1

        if not any(len(word.rstrip(".")) > 1 for word in words):
            return False

        column_tokens = set(re.findall(r"[a-z]+", column_name.lower()))
        has_column_hint = column_name.lower() in cls._NAME_COLUMN_HINTS or (
            "name" in column_tokens
            and not column_tokens & {"product", "item", "company", "city", "file", "table"}
        )
        has_known_token = any(word.casefold() in cls._NAME_TOKENS for word in words)
        return has_column_hint or has_honorific or has_initial or has_known_token

    @classmethod
    def _is_valid_postal_address(cls, val: str, column_name: str) -> bool:
        """Recognize standalone address-shaped text, rather than ticket prose."""
        if not 20 <= len(val) <= 250 or len(val.split()) > 35:
            return False

        words = set(re.findall(r"[a-z]+", val.lower()))
        if words & {"please", "refund", "call", "email", "verify", "uploading", "support", "update"}:
            return False

        address_words = words & {
            "road", "rd", "street", "st", "marg", "nagar", "layout", "sector",
            "cross", "main", "flat", "floor", "block", "dist", "district",
            "near", "house", "plot", "tower", "lane", "avenue", "colony",
        }
        if len(address_words) < 2:
            return False

        if "address" in column_name.lower():
            return True

        # With no metadata hint, require a house/flat number near the start.
        return bool(re.match(
            r"(?i)^(?:(?:flat|house|plot|no|block|floor)\.?\s*(?:no\.?\s*)?)?[a-z]?-?[0-9]",
            val,
        ))

    @classmethod
    def classify_column(
        cls, column_name: str, data_type: str, samples: list[str]
    ) -> dict[str, Any]:
        """Analyzes column samples and metadata to determine PII type, confidence, and risk."""
        logger.info(
            "Classifying column=%s sample_count=%d", column_name, len(samples)
        )
        if not samples:
            return {
                "inferred_pii_type": "NONE",
                "embedded_pii_types": [],
                "confidence": 0.0,
                "match_ratio": 0.0,
                "embedded_match_ratio": 0.0,
                "embedded_confidence": 0.0,
                "risk_level": "NONE",
                "masked_evidence": [],
                "justification": "Column contains 0 non-null values or samples.",
            }

        # Counters for value matches
        match_counts = {
            "EMAIL": 0,
            "PHONE_IN": 0,
            "PAN": 0,
            "AADHAAR": 0,
            "PINCODE": 0,
            "DOB": 0,
            "FULL_NAME": 0,
            "POSTAL_ADDRESS": 0,
        }
        total_samples = len(samples)

        # Free-text detection counters for unstructured text columns (e.g. notes, body)
        embedded_hits = set()
        embedded_hit_rows = 0
        sample_value_types = []
        is_free_text_col = data_type.lower().split("(", 1)[0].strip() in {
            "text", "varchar", "character varying", "char", "character"
        }

        for val in samples:
            val_clean = str(val).strip()

            value_matches = {
                "EMAIL": cls._is_valid_email(val_clean),
                "PHONE_IN": cls._is_valid_phone(val_clean),
                "PAN": cls._is_valid_pan(val_clean),
                "AADHAAR": bool(val_clean) and val_clean[0] in "23456789"
                and cls._validate_verhoeff(val_clean),
                "PINCODE": cls._is_valid_pincode(val_clean) and not any(
                    k in column_name.lower() for k in {"id", "amount", "price", "count", "total", "invoice"}
                ),
                "DOB": cls._is_valid_dob(val_clean, column_name),
                "FULL_NAME": is_free_text_col and cls._is_valid_full_name(val_clean, column_name),
                "POSTAL_ADDRESS": is_free_text_col and cls._is_valid_postal_address(val_clean, column_name),
            }
            value_types = [pii_type for pii_type, matches in value_matches.items() if matches]
            sample_value_types.append(value_types)
            for pii_type in value_types:
                match_counts[pii_type] += 1

            # Free-text embedded scan
            if is_free_text_col:
                row_embedded_types = set()
                detectors = (
                    ("EMAIL", EMAIL_PATTERN, cls._is_valid_email),
                    ("PHONE_IN", PHONE_IN_TEXT, cls._is_valid_phone),
                    ("PAN", PAN_IN_TEXT, cls._is_valid_pan),
                    ("AADHAAR", r"(?<!\w)[2-9][0-9]{11}(?!\w)", cls._validate_verhoeff),
                )
                for pii_type, pattern, validator in detectors:
                    if any(
                        match.span() != (0, len(val_clean)) and validator(match.group())
                        for match in re.finditer(pattern, val_clean)
                    ):
                        row_embedded_types.add(pii_type)
                if row_embedded_types:
                    embedded_hit_rows += 1
                    embedded_hits.update(row_embedded_types)

        # Determine primary PII type with highest match ratio >= 0.25 threshold
        best_type = "NONE"
        best_ratio = 0.0

        for pii_type, count in match_counts.items():
            ratio = count / total_samples
            if ratio > best_ratio:
                best_ratio = ratio
                best_type = pii_type

        if best_ratio < 0.25:
            best_type = "NONE"
            best_ratio = 0.0

        confidence = calculate_confidence(best_ratio, total_samples)
        embedded_ratio = embedded_hit_rows / total_samples
        embedded_confidence = calculate_confidence(embedded_ratio, total_samples)
        embedded_list = sorted(embedded_hits) if is_free_text_col else []
        risk_types = sorted(
            {pii_type for pii_type, count in match_counts.items() if count > 0}
            | embedded_hits
        )
        risk_level = determine_risk_level(risk_types)

        # Generate masked evidence samples
        masked_evidence = []
        for val, value_types in zip(samples[:3], sample_value_types[:3]):
            if value_types:
                evidence_type = best_type if best_type in value_types else value_types[0]
                evidence = mask_value(evidence_type, str(val))
                # Redact other identifiers that may occur in retained email domains.
                masked_evidence.append(mask_free_text(evidence, ["PHONE_IN", "PAN", "AADHAAR"]))
            elif best_type != "NONE":
                masked_evidence.append("[MIXED_CONTENT_REDACTED]")
            elif is_free_text_col and embedded_list:
                masked_evidence.append(mask_free_text(val, embedded_list))
            else:
                masked_evidence.append("[UNCLASSIFIED_REDACTED]")

        justification = (
            f"Classified as {best_type} based on {best_ratio * 100:.1f}% value match ratio "
            f"across {total_samples} sampled rows. "
            f"Primary sample-weighted score: {confidence}; scores are heuristic, not probabilities."
        )
        if is_free_text_col and embedded_list:
            justification += (
                f" Detected embedded PII: {', '.join(embedded_list)} "
                f"in {embedded_hit_rows}/{total_samples} sampled rows "
                f"({embedded_ratio * 100:.1f}%; embedded score: {embedded_confidence})."
            )

        if risk_types:
            justification += (
                f" Risk {risk_level} considers all validated standalone and embedded types: "
                f"{', '.join(risk_types)}."
            )

        return {
            "inferred_pii_type": best_type,
            "embedded_pii_types": embedded_list,
            "confidence": confidence,
            "match_ratio": round(best_ratio, 4),
            "embedded_match_ratio": round(embedded_ratio, 4),
            "embedded_confidence": embedded_confidence,
            "risk_level": risk_level,
            "masked_evidence": masked_evidence,
            "justification": justification,
        }
