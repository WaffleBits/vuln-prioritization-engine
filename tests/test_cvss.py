import pytest

from vpe.cvss import CvssError, roundup, score, severity

# Expected scores from the FIRST CVSS v3.1 calculator.
KNOWN = [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H", 7.4),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
]


@pytest.mark.parametrize("vector,expected", KNOWN)
def test_known_vectors(vector, expected):
    assert score(vector).base_score == expected


def test_roundup_matches_spec_examples():
    assert roundup(4.02) == 4.1
    assert roundup(4.00) == 4.0
    # Floating point noise must not push an exact tenth up a step.
    assert roundup(0.1 + 0.2) == 0.3


@pytest.mark.parametrize("value,label", [(0, "None"), (3.9, "Low"), (4.0, "Medium"),
                                         (6.9, "Medium"), (7.0, "High"), (9.0, "Critical")])
def test_severity_bands(value, label):
    assert severity(value) == label


@pytest.mark.parametrize("vector", [
    "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",             # no prefix
    "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",             # wrong version
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",        # missing A
    "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",    # bad value
    "CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # duplicate
])
def test_rejects_bad_vectors(vector):
    with pytest.raises(CvssError):
        score(vector)


def test_temporal_metrics_are_ignored_for_base():
    v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C"
    assert score(v).base_score == 9.8


def test_flags():
    s = score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H")
    assert s.network_reachable and s.no_privileges and s.needs_user
