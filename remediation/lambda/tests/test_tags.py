import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from handler import enforcing, tags_permit_remediation

OK = {"AutoRemediate": "enabled", "Project": "cloud-security-guardrails"}


def test_correct_tags_permit():
    permitted, _ = tags_permit_remediation(OK)
    assert permitted is True


def test_no_tags_denied():
    permitted, reason = tags_permit_remediation({})
    assert permitted is False
    assert "no tags" in reason


def test_missing_autoremediate_denied():
    permitted, reason = tags_permit_remediation(
        {"Project": "cloud-security-guardrails"}
    )
    assert permitted is False
    assert "AutoRemediate" in reason


def test_autoremediate_disabled_denied():
    """The dev landing zone carries AutoRemediate=disabled."""
    tags = dict(OK, AutoRemediate="disabled")
    permitted, reason = tags_permit_remediation(tags)
    assert permitted is False
    assert "disabled" in reason


def test_wrong_project_denied():
    tags = dict(OK, Project="some-other-project")
    permitted, reason = tags_permit_remediation(tags)
    assert permitted is False
    assert "Project" in reason


def test_enforce_defaults_false(monkeypatch):
    monkeypatch.delenv("ENFORCE", raising=False)
    assert enforcing() is False


def test_enforce_requires_exact_true(monkeypatch):
    for value in ["false", "False", "yes", "1", "TRUE_ISH", ""]:
        monkeypatch.setenv("ENFORCE", value)
        assert enforcing() is (value.lower() == "true")
