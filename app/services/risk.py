def calculate_confidence(match_ratio: float, sample_size: int) -> float:
    """Heuristic match support weighted by sample size, not a calibrated probability."""
    if sample_size == 0:
        return 0.0
    sample_weight = min(1.0, sample_size / 20.0)
    return round(match_ratio * sample_weight, 2)


def determine_risk_level(detected_types: list[str]) -> str:
    """Use the highest tier among all validated sample types, regardless of frequency."""
    all_types = set(detected_types)

    # CRITICAL: Immutable government/financial identifiers with severe regulatory impact
    if {"PAN", "AADHAAR"} & all_types:
        return "CRITICAL"

    # HIGH: Direct contact vectors, identity verification fields, or unindexed free-text PII
    if {"EMAIL", "PHONE_IN", "POSTAL_ADDRESS", "DOB", "FREE_TEXT"} & all_types:
        return "HIGH"

    # MEDIUM: Identifiers requiring combination to act as direct vectors
    if "FULL_NAME" in all_types:
        return "MEDIUM"

    # LOW: Quasi-identifiers or broad geographic cohorts
    if "PINCODE" in all_types:
        return "LOW"

    return "NONE"
