import re

EMAIL_PATTERN = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
PAN_PATTERN = r"[A-Z]{3}[ABCFGHJLPT][A-Z][0-9]{4}[A-Z]"
PHONE_PATTERN = r"(?:(?:\+91|91|0)[ -]?)?[6-9](?:[ -]?[0-9]){9}"
PAN_IN_TEXT = rf"(?<!\w){PAN_PATTERN}(?!\w)"
PHONE_IN_TEXT = rf"(?<![\w+]){PHONE_PATTERN}(?!\w)"


def mask_value(pii_type: str, value: str) -> str:
    """Masks a sensitive value while preserving identifiable metadata format."""
    if not value:
        return ""
    val_str = str(value).strip()

    if pii_type == "EMAIL":
        if not re.fullmatch(EMAIL_PATTERN, val_str):
            return "[EMAIL_REDACTED]"
        name, domain = val_str.split("@")
        prefix = name[:2] if len(name) > 2 else ""
        masked_name = prefix + "*" * (len(name) - len(prefix))
        return f"{masked_name}@{domain}"

    elif pii_type == "PHONE_IN":
        digits = re.sub(r"\D", "", val_str)
        if len(digits) >= 4:
            last4 = digits[-4:]
            return f"+91-******{last4}"
        return "******"

    elif pii_type == "PAN":
        if len(val_str) >= 10:
            return val_str[:3] + "******" + val_str[-1:]
        return "ABC******F"

    elif pii_type == "AADHAAR":
        return "XXXX-XXXX-" + val_str[-4:] if len(val_str) >= 4 else "XXXX-XXXX-XXXX"

    elif pii_type == "FULL_NAME":
        words = val_str.split()
        masked_words = [
            (w[0] + "*" * (len(w) - 1) if len(w) > 1 else "*") for w in words
        ]
        return " ".join(masked_words)

    elif pii_type == "PINCODE":
        if len(val_str) >= 6:
            return val_str[:2] + "****"
        return "******"

    elif pii_type == "DOB":
        return "****-**-**"

    elif pii_type == "POSTAL_ADDRESS":
        return "[ADDRESS_REDACTED]"

    return "******"


def mask_free_text(text: str, detected_types: list[str]) -> str:
    """Masks sensitive entities embedded inside free-text prose."""
    masked = text
    if "EMAIL" in detected_types:
        masked = re.sub(
            EMAIL_PATTERN, "[EMAIL_REDACTED]", masked
        )
    if "PHONE_IN" in detected_types:
        masked = re.sub(
            PHONE_IN_TEXT,
            "[PHONE_REDACTED]",
            masked,
        )
    if "PAN" in detected_types:
        masked = re.sub(
            PAN_IN_TEXT,
            "[PAN_REDACTED]",
            masked,
        )
    if "AADHAAR" in detected_types:
        masked = re.sub(r"\b[2-9]\d{11}\b", "[AADHAAR_REDACTED]", masked)
    return masked
