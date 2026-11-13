import pytest
from conftest import CRIT_NET, DOS, HIGH_LOCAL

from vpe.attack import map_technique
from vpe.cvss import score

XSS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
CLIENT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
LEAK = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"


@pytest.mark.parametrize("vector,cwes,exposed,expected", [
    (CRIT_NET, (), True, "T1190"),
    (CRIT_NET, (), False, "T1210"),
    (HIGH_LOCAL, (), False, "T1068"),
    (CLIENT, (), False, "T1203"),
    (XSS, ("CWE-79",), True, "T1189"),
    (DOS, ("CWE-400",), True, "T1499.004"),
    (LEAK, ("CWE-522",), True, "T1212"),
])
def test_mapping(vector, cwes, exposed, expected):
    assert map_technique(score(vector), cwes, exposed).technique == expected


def test_no_vector_falls_back_on_exposure():
    assert map_technique(None, (), True).technique == "T1190"
    assert map_technique(None, (), False).technique == "T1210"
