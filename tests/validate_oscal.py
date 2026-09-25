"""Validate a ScubaLens OSCAL export against the OSCAL Assessment Results model.

Uses compliance-trestle, an open-source OSCAL toolkit (https://github.com/oscal-compass/compliance-trestle).

Usage (from the repository root):
    pip install compliance-trestle
    python tests/validate_oscal.py                     # checks the committed sample export
    python tests/validate_oscal.py path/to/export.json # checks a file you exported from the dashboard

Exit code 0 = valid, 1 = invalid.
"""
import json
import sys
from pathlib import Path

from trestle.oscal.assessment_results import AssessmentResults

ROOT = Path(__file__).resolve().parent.parent
DEFAULT = ROOT / "samples" / "ScubaLens_OSCAL_Assessment_Results.json"


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT
    doc = json.loads(path.read_text(encoding="utf-8"))

    try:
        ar = AssessmentResults(**doc["assessment-results"])
    except Exception as exc:  # pydantic raises a detailed validation error
        print(f"[FAIL] {path.name} is not valid OSCAL assessment results:\n{exc}")
        return 1

    result = ar.results[0]
    findings = result.findings or []
    observations = {o.uuid for o in (result.observations or [])}

    def prop(f, name):
        return next((p.value for p in (f.props or []) if p.name == name), None)

    checks = [
        ("Document parses as OSCAL assessment results", True),
        (f"Contains at least one finding ({len(findings)} found)", len(findings) >= 1),
        ("Every finding carries its SCuBA policy ID",
         all(prop(f, "scuba-policy-id") for f in findings)),
        ("Every finding links to an observation in this document",
         all(f.related_observations and all(r.observation_uuid in observations for r in f.related_observations) for f in findings)),
        ("Every finding has a remediation script or is routed to an engineer",
         all(prop(f, "remediation-script") or "Routed to engineer" in (prop(f, "remediation-status") or "") for f in findings)),
    ]
    ok = True
    for name, passed in checks:
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}")
        ok = ok and passed
    print(f"\n{path.name}: {'valid' if ok else 'INVALID'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
