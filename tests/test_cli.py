"""Tests for chainvalidator.cli."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from chainvalidator import __version__
from chainvalidator.cli import _validate_domain, _validate_record_type, app
from chainvalidator.models import DNSSECReport, Status

runner = CliRunner()


# ---------------------------------------------------------------------------
# _validate_domain
# ---------------------------------------------------------------------------


class TestValidateDomain:
    def test_valid_domain_returned_unchanged(self):
        assert _validate_domain("example.com") == "example.com"
        assert _validate_domain("sub.example.com") == "sub.example.com"
        assert _validate_domain("example.com.") == "example.com."

    def test_invalid_domain_raises_bad_parameter(self):
        import typer

        with pytest.raises(typer.BadParameter):
            _validate_domain("localhost")

    def test_single_label_raises(self):
        import typer

        with pytest.raises(typer.BadParameter):
            _validate_domain("notadomain")

    def test_empty_string_raises(self):
        import typer

        with pytest.raises(typer.BadParameter):
            _validate_domain("")


# ---------------------------------------------------------------------------
# _validate_record_type
# ---------------------------------------------------------------------------


class TestValidateRecordType:
    def test_valid_types_uppercased(self):
        assert _validate_record_type("a") == "A"
        assert _validate_record_type("AAAA") == "AAAA"
        assert _validate_record_type("mx") == "MX"

    def test_invalid_type_raises_bad_parameter(self):
        import typer

        with pytest.raises(typer.BadParameter):
            _validate_record_type("NOTATYPE")


# ---------------------------------------------------------------------------
# CLI: --version
# ---------------------------------------------------------------------------


class TestCLIVersion:
    def test_version_flag(self):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert __version__ in result.output


# ---------------------------------------------------------------------------
# CLI: info sub-commands
# ---------------------------------------------------------------------------


class TestCLIInfo:
    def test_algorithms(self):
        result = runner.invoke(app, ["info", "algorithms"])
        assert result.exit_code == 0
        assert "ECDSAP256SHA256" in result.output or "Algorithm" in result.output

    def test_digests(self):
        result = runner.invoke(app, ["info", "digests"])
        assert result.exit_code == 0
        assert "SHA-256" in result.output or "Digest" in result.output

    def test_root_servers(self):
        result = runner.invoke(app, ["info", "root-servers"])
        assert result.exit_code == 0
        assert "root-servers.net" in result.output


# ---------------------------------------------------------------------------
# CLI: check command
# ---------------------------------------------------------------------------


def _make_report(status: Status = Status.SECURE) -> DNSSECReport:
    return DNSSECReport(domain="example.com", record_type="A", status=status)


class TestCLICheck:
    def _patch_assess(self, report: DNSSECReport):
        return patch("chainvalidator.cli.assess", return_value=report)

    def _patch_print(self):
        return patch("chainvalidator.cli.print_full_report")

    def test_invalid_domain_exits_2(self):
        result = runner.invoke(app, ["check", "localhost"])
        assert result.exit_code == 2

    def test_secure_exits_0(self):
        report = _make_report(Status.SECURE)
        with self._patch_assess(report), self._patch_print():
            result = runner.invoke(app, ["check", "example.com"])
        assert result.exit_code == 0

    def test_insecure_exits_2(self):
        report = _make_report(Status.INSECURE)
        with self._patch_assess(report), self._patch_print():
            result = runner.invoke(app, ["check", "example.com"])
        assert result.exit_code == 2

    def test_bogus_exits_1(self):
        report = _make_report(Status.BOGUS)
        with self._patch_assess(report), self._patch_print():
            result = runner.invoke(app, ["check", "example.com"])
        assert result.exit_code == 1

    def test_error_status_exits_1(self):
        report = _make_report(Status.ERROR)
        with self._patch_assess(report), self._patch_print():
            result = runner.invoke(app, ["check", "example.com"])
        assert result.exit_code == 1

    def test_value_error_from_assess_exits_1(self):
        with patch("chainvalidator.cli.assess", side_effect=ValueError("bad")):
            result = runner.invoke(app, ["check", "example.com"])
        assert result.exit_code == 1

    def test_passes_record_type_option(self):
        report = _make_report(Status.SECURE)
        with patch("chainvalidator.cli.assess", return_value=report) as mock_assess:
            with self._patch_print():
                runner.invoke(app, ["check", "example.com", "--type", "AAAA"])
        call_kwargs = mock_assess.call_args
        assert call_kwargs.kwargs.get("record_type") == "AAAA" or "AAAA" in str(
            call_kwargs
        )

    def test_passes_timeout_option(self):
        report = _make_report(Status.SECURE)
        with patch("chainvalidator.cli.assess", return_value=report) as mock_assess:
            with self._patch_print():
                runner.invoke(app, ["check", "example.com", "--timeout", "10.0"])
        call_kwargs = mock_assess.call_args
        assert call_kwargs.kwargs.get("timeout") == 10.0 or "10.0" in str(call_kwargs)

    def test_print_full_report_called(self):
        report = _make_report(Status.SECURE)
        with self._patch_assess(report):
            with patch("chainvalidator.cli.print_full_report") as mock_print:
                runner.invoke(app, ["check", "example.com"])
        mock_print.assert_called_once_with(report)

    def test_invalid_record_type_handled(self):
        result = runner.invoke(app, ["check", "example.com", "--type", "NOTATYPE"])
        # Typer reports bad parameter as exit code 2
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# CLI: check --output flag
# ---------------------------------------------------------------------------


class TestCLICheckOutput:
    """Tests for the ``--output / -o`` export flag on ``chainvalidator check``."""

    def _make_report(self, status: Status = Status.SECURE) -> DNSSECReport:
        return DNSSECReport(domain="example.com", record_type="A", status=status)

    def test_output_txt_calls_save_report(self, tmp_path):
        """--output FILE.txt calls save_report with the correct path."""
        dest = str(tmp_path / "out.txt")
        report = self._make_report()
        with (
            patch("chainvalidator.cli.assess", return_value=report),
            patch("chainvalidator.cli.print_full_report"),
            patch("chainvalidator.cli.save_report") as mock_save,
        ):
            result = runner.invoke(app, ["check", "example.com", "--output", dest])
        assert result.exit_code == 0
        mock_save.assert_called_once_with(dest)

    def test_output_svg_calls_save_report(self, tmp_path):
        dest = str(tmp_path / "out.svg")
        report = self._make_report()
        with (
            patch("chainvalidator.cli.assess", return_value=report),
            patch("chainvalidator.cli.print_full_report"),
            patch("chainvalidator.cli.save_report") as mock_save,
        ):
            result = runner.invoke(app, ["check", "example.com", "--output", dest])
        assert result.exit_code == 0
        mock_save.assert_called_once_with(dest)

    def test_output_html_calls_save_report(self, tmp_path):
        dest = str(tmp_path / "out.html")
        report = self._make_report()
        with (
            patch("chainvalidator.cli.assess", return_value=report),
            patch("chainvalidator.cli.print_full_report"),
            patch("chainvalidator.cli.save_report") as mock_save,
        ):
            result = runner.invoke(app, ["check", "example.com", "--output", dest])
        assert result.exit_code == 0
        mock_save.assert_called_once_with(dest)

    def test_output_value_error_exits_1(self, tmp_path):
        """ValueError from save_report (bad extension) must exit with code 1."""
        dest = str(tmp_path / "out.pdf")
        report = self._make_report()
        with (
            patch("chainvalidator.cli.assess", return_value=report),
            patch("chainvalidator.cli.print_full_report"),
            patch(
                "chainvalidator.cli.save_report",
                side_effect=ValueError("Unsupported export format"),
            ),
        ):
            result = runner.invoke(app, ["check", "example.com", "--output", dest])
        assert result.exit_code == 1

    def test_output_oserror_exits_1(self, tmp_path):
        """OSError from save_report (e.g. permission denied) must exit with code 1."""
        dest = str(tmp_path / "out.txt")
        report = self._make_report()
        with (
            patch("chainvalidator.cli.assess", return_value=report),
            patch("chainvalidator.cli.print_full_report"),
            patch(
                "chainvalidator.cli.save_report",
                side_effect=OSError("permission denied"),
            ),
        ):
            result = runner.invoke(app, ["check", "example.com", "--output", dest])
        assert result.exit_code == 1

    def test_no_output_does_not_call_save_report(self):
        """When --output is omitted, save_report is never called."""
        report = self._make_report()
        with (
            patch("chainvalidator.cli.assess", return_value=report),
            patch("chainvalidator.cli.print_full_report"),
            patch("chainvalidator.cli.save_report") as mock_save,
        ):
            runner.invoke(app, ["check", "example.com"])
        mock_save.assert_not_called()

    def test_output_short_flag(self, tmp_path):
        """-o is the short form of --output."""
        dest = str(tmp_path / "out.txt")
        report = self._make_report()
        with (
            patch("chainvalidator.cli.assess", return_value=report),
            patch("chainvalidator.cli.print_full_report"),
            patch("chainvalidator.cli.save_report") as mock_save,
        ):
            result = runner.invoke(app, ["check", "example.com", "-o", dest])
        assert result.exit_code == 0
        mock_save.assert_called_once_with(dest)
