"""Tests for chainvalidator.assessor."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from chainvalidator.assessor import assess
from chainvalidator.models import DNSSECReport, Status


def _make_report(status: Status = Status.SECURE) -> DNSSECReport:
    r = DNSSECReport(domain="example.com", record_type="A", status=status)
    return r


class TestAssess:
    def _patch_checker(self, report: DNSSECReport):
        """Return a context manager that patches DNSSECChecker."""
        checker_instance = MagicMock()
        checker_instance.report = report
        checker_instance.check.return_value = True
        return patch(
            "chainvalidator.assessor.DNSSECChecker", return_value=checker_instance
        )

    def test_returns_dnssec_report(self):
        report = _make_report(Status.SECURE)
        with self._patch_checker(report):
            result = assess("example.com")
        assert isinstance(result, DNSSECReport)
        assert result is report

    def test_passes_record_type_and_timeout(self):
        report = _make_report()
        with self._patch_checker(report):
            with patch("chainvalidator.assessor.DNSSECChecker") as MockChecker:
                instance = MagicMock()
                instance.report = report
                MockChecker.return_value = instance
                assess("example.com", record_type="AAAA", timeout=3.0)
        MockChecker.assert_called_once_with(
            "example.com", record_type="AAAA", timeout=3.0
        )

    def test_calls_checker_check(self):
        report = _make_report()
        with patch("chainvalidator.assessor.DNSSECChecker") as MockChecker:
            instance = MagicMock()
            instance.report = report
            MockChecker.return_value = instance
            assess("example.com")
        instance.check.assert_called_once()

    def test_progress_cb_called_when_provided(self):
        report = _make_report()
        calls = []
        with self._patch_checker(report):
            assess("example.com", progress_cb=calls.append)
        assert len(calls) >= 2
        assert any("example.com" in c for c in calls)

    def test_progress_cb_none_is_fine(self):
        report = _make_report()
        with self._patch_checker(report):
            # Should not raise
            result = assess("example.com", progress_cb=None)
        assert result is report

    def test_raises_value_error_for_invalid_domain(self):
        with pytest.raises(ValueError):
            assess("notadomain")

    def test_raises_value_error_for_bad_record_type(self):
        with pytest.raises(ValueError):
            assess("example.com", record_type="NOTATYPE")
