import pytest

from app.services.risk import calculate_confidence


@pytest.mark.parametrize("ratio,size,expected", [
    (1.0, 0, 0.0), (1.0, 1, 0.05), (1.0, 8, 0.4),
    (1.0, 19, 0.95), (1.0, 20, 1.0), (1.0, 21, 1.0),
    (0.5, 10, 0.25), (0.5, 20, 0.5), (0.0, 100, 0.0),
])
def test_confidence_is_sample_weighted_support_with_saturation(ratio, size, expected):
    assert calculate_confidence(ratio, size) == expected
