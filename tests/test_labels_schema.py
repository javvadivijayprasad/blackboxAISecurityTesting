from pathlib import Path
from paperk_oracle.labels import load, validate_raw
import yaml

EX = Path(__file__).resolve().parent.parent / "labels" / "examples" / "DVWA.labels.example.yaml"


def test_example_conforms_and_loads():
    entries = yaml.safe_load(EX.read_text())
    assert validate_raw(entries) == []            # no schema errors
    labels = load(EX)
    assert len(labels) == 6
    assert sum(1 for l in labels if l.is_vulnerable) == 4
    assert sum(1 for l in labels if not l.is_vulnerable) == 2   # negative controls present


def test_negative_controls_have_no_outcome():
    for l in load(EX):
        if not l.is_vulnerable:
            assert l.outcome_type == "none" and l.oracle_check == "none"
