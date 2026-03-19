"""chainvalidator CLI – DNSSEC chain-of-trust validation.

Sub-commands
------------
check       Validate the full DNSSEC chain for a domain.
info        Show protocol reference tables (algorithms, digest types, root servers).

Usage examples::

    chainvalidator check example.com
    chainvalidator check example.com --type AAAA
    chainvalidator check example.com --type MX --timeout 10
    chainvalidator info algorithms
    chainvalidator info digests
    chainvalidator info root-servers
"""

from __future__ import annotations

import re
from typing import Annotated, Optional

import dns.rdatatype
import typer
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from chainvalidator import __version__
from chainvalidator.assessor import assess
from chainvalidator.constants import (
    ALGORITHM_MAP,
    DIGEST_MAP,
    DNS_TIMEOUT,
    ROOT_SERVERS,
)
from chainvalidator.models import Status
from chainvalidator.reporter import console, print_full_report

# ---------------------------------------------------------------------------
# Typer application
# ---------------------------------------------------------------------------

app = typer.Typer(
    name="chainvalidator",
    help=(
        "DNSSEC Chain-of-Trust Validator.\n\n"
        "Validates the full chain: Trust Anchor → . → TLD → SLD → domain."
    ),
    add_completion=False,
)

info_app = typer.Typer(
    name="info",
    help="Show protocol reference tables (algorithms, digest types, root servers).",
)
app.add_typer(info_app, name="info")

# ---------------------------------------------------------------------------
# Input validators
# ---------------------------------------------------------------------------

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\."
    r"[a-zA-Z]{2,63}\.?$"
)


def _validate_domain(value: str) -> str:
    """Reject input that is not a valid fully-qualified domain name.

    Requires at least two DNS labels (e.g. ``"example.com"``).
    Single-label names such as ``"localhost"`` are rejected.

    :param value: Raw string from the CLI argument.
    :type value: str
    :returns: The validated domain string unchanged.
    :rtype: str
    :raises typer.BadParameter: If *value* is not a valid domain name.
    """
    if not _DOMAIN_RE.match(value):
        raise typer.BadParameter(f"'{value}' is not a valid domain name")
    return value


def _validate_record_type(value: str) -> str:
    """Reject input that is not a recognised DNS record type.

    :param value: Raw string from the CLI option.
    :type value: str
    :returns: The validated record type in upper-case.
    :rtype: str
    :raises typer.BadParameter: If *value* is not a known RR type.
    """
    try:
        dns.rdatatype.from_text(value.upper())
    except Exception:
        raise typer.BadParameter(
            f"'{value}' is not a recognised DNS record type. "
            f"Common types: A, AAAA, MX, NS, TXT, CNAME"
        )
    return value.upper()


# ---------------------------------------------------------------------------
# Version callback
# ---------------------------------------------------------------------------


def _version_callback(value: bool) -> None:  # pragma: no cover
    if value:
        typer.echo(f"chainvalidator {__version__}")
        raise typer.Exit()


@app.callback()
def _main(
    version: Annotated[
        Optional[bool],
        typer.Option(
            "--version",
            "-V",
            callback=_version_callback,
            is_eager=True,
            help="Show version and exit.",
        ),
    ] = None,
) -> None:
    """chainvalidator – DNSSEC Chain-of-Trust Validator.

    :param version: When ``True``, print the version and exit (injected by Typer).
    :type version: bool or None
    """


# ---------------------------------------------------------------------------
# check command
# ---------------------------------------------------------------------------


@app.command("check")
def cmd_check(
    domain: Annotated[
        str,
        typer.Argument(
            help="Domain name to validate (e.g. example.com).",
            callback=_validate_domain,
        ),
    ],
    record_type: Annotated[
        str,
        typer.Option(
            "--type",
            "-t",
            help="DNS record type to validate at the leaf.",
            callback=_validate_record_type,
        ),
    ] = "A",
    timeout: Annotated[
        float,
        typer.Option(
            "--timeout",
            help="Per-query UDP/TCP timeout in seconds.",
        ),
    ] = DNS_TIMEOUT,
) -> None:
    """Validate the full DNSSEC chain of trust for DOMAIN.

    :param domain: Fully-qualified domain name to validate.
    :type domain: str
    :param record_type: DNS record type to validate at the leaf (default ``"A"``).
    :type record_type: str
    :param timeout: Per-query UDP/TCP timeout in seconds.
    :type timeout: float

    Exit codes:

    \\b
      0  fully secure
      2  insecure delegation (chain not anchored end-to-end)
      1  bogus / validation failed
    """
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console,
    ) as progress:
        task = progress.add_task("Resolving zone hierarchy …", total=None)

        def _progress_cb(msg: str) -> None:  # pragma: no cover
            progress.update(task, description=msg)

        try:
            report = assess(
                domain,
                record_type=record_type,
                timeout=timeout,
                progress_cb=_progress_cb,
            )
        except ValueError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(code=1)

    print_full_report(report)

    if report.status is Status.SECURE:
        raise typer.Exit(code=0)
    elif report.status is Status.INSECURE:
        raise typer.Exit(code=2)
    else:
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# info sub-commands
# ---------------------------------------------------------------------------


@info_app.command("algorithms")
def cmd_info_algorithms() -> None:
    """List all DNSSEC algorithm numbers and their names (RFC 8624)."""
    tbl = Table(show_header=True, header_style="bold blue", padding=(0, 1))
    tbl.add_column("Number", justify="right", style="dim")
    tbl.add_column("Mnemonic", style="bold")
    for num in sorted(ALGORITHM_MAP):
        tbl.add_row(str(num), ALGORITHM_MAP[num])
    console.print(
        Panel("[bold]DNSSEC Algorithm Numbers[/bold] (RFC 8624)", style="blue")
    )
    console.print(tbl)


@info_app.command("digests")
def cmd_info_digests() -> None:
    """List DS digest type numbers and their names (RFC 4034 §5.1)."""
    tbl = Table(show_header=True, header_style="bold blue", padding=(0, 1))
    tbl.add_column("Number", justify="right", style="dim")
    tbl.add_column("Name", style="bold")
    for num in sorted(DIGEST_MAP):
        tbl.add_row(str(num), DIGEST_MAP[num])
    console.print(
        Panel("[bold]DS Digest Type Numbers[/bold] (RFC 4034 §5.1)", style="blue")
    )
    console.print(tbl)


@info_app.command("root-servers")
def cmd_info_root_servers() -> None:
    """List all 13 IANA root name servers and their IPv4 addresses."""
    tbl = Table(show_header=True, header_style="bold blue", padding=(0, 1))
    tbl.add_column("Hostname", style="bold")
    tbl.add_column("IPv4 Address", style="dim")
    for hostname, ip in sorted(ROOT_SERVERS.items()):
        tbl.add_row(hostname, ip)
    console.print(Panel("[bold]IANA Root Name Servers[/bold]", style="blue"))
    console.print(tbl)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":  # pragma: no cover
    app()
