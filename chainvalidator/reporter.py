"""Rich terminal reporter for chainvalidator results.

All ``print_*`` functions accept the corresponding model objects and render
them to the terminal using Rich tables and panels.  The module-level
``console`` instance can be imported by other modules that need to write to
the same output stream.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from chainvalidator.models import ChainLink, DNSSECReport, Status

console = Console()

# ---------------------------------------------------------------------------
# Status styling
# ---------------------------------------------------------------------------

_STATUS_STYLE: dict[Status, tuple[str, str]] = {
    Status.SECURE: ("✔", "bold green"),
    Status.INSECURE: ("⚠", "bold yellow"),
    Status.BOGUS: ("✘", "bold red"),
    Status.ERROR: ("✘", "bold red"),
}


def _status_text(status: Status) -> Text:
    """Return a styled Rich :class:`~rich.text.Text` for a :class:`~chainvalidator.models.Status` value.

    :param status: The status to render.
    :type status: ~chainvalidator.models.Status
    :returns: Styled text with icon and status label.
    :rtype: ~rich.text.Text
    """
    icon, style = _STATUS_STYLE.get(status, ("?", "bold magenta"))
    return Text(f"{icon} {status.value.upper()}", style=style)


def _status_panel_style(status: Status) -> str:
    """Return the Rich panel border colour for *status*.

    :param status: The status to map.
    :type status: ~chainvalidator.models.Status
    :returns: A Rich colour string.
    :rtype: str
    """
    return {
        Status.SECURE: "green",
        Status.INSECURE: "yellow",
        Status.BOGUS: "red",
        Status.ERROR: "red",
    }.get(status, "white")


# ---------------------------------------------------------------------------
# Chain table
# ---------------------------------------------------------------------------


def _chain_table(chain: list[ChainLink]) -> Table:
    """Build a Rich table showing the full DS → DNSKEY chain.

    :param chain: List of :class:`~chainvalidator.models.ChainLink` objects.
    :type chain: list[~chainvalidator.models.ChainLink]
    :returns: Formatted Rich table.
    :rtype: ~rich.table.Table
    """
    tbl = Table(
        show_header=True,
        header_style="bold blue",
        expand=True,
        padding=(0, 1),
    )
    tbl.add_column("Zone", style="bold", no_wrap=True)
    tbl.add_column("Status", justify="center")
    tbl.add_column("DS Records")
    tbl.add_column("DNSKEY Records")
    tbl.add_column("Matches / Notes")

    for link in chain:
        ds_cell = "\n".join(link.ds_records) if link.ds_records else "—"
        key_cell = "\n".join(link.dnskeys) if link.dnskeys else "—"
        note_cell = "\n".join(
            link.ds_matched + link.notes + link.warnings + link.errors
        )

        tbl.add_row(
            link.zone,
            _status_text(link.status),
            ds_cell,
            key_cell,
            note_cell or "—",
        )

    return tbl


# ---------------------------------------------------------------------------
# Individual section printers
# ---------------------------------------------------------------------------


def print_trust_anchor(report: DNSSECReport) -> None:
    """Render the IANA trust anchor summary panel.

    :param report: The full validation report.
    :type report: ~chainvalidator.models.DNSSECReport
    """
    console.print(
        Panel("[bold]Trust Anchor[/bold] – IANA root-anchors.xml", style="blue")
    )
    if report.trust_anchor_keys:
        for key in report.trust_anchor_keys:
            console.print(f"  [green]✔[/green] {key} — active")
    else:
        console.print("  [red]No active trust anchor keys found[/red]")


def print_chain(report: DNSSECReport) -> None:
    """Render the chain-of-trust table.

    :param report: The full validation report.
    :type report: ~chainvalidator.models.DNSSECReport
    """
    console.print(
        Panel(
            f"[bold]Chain of Trust[/bold] – {report.domain} ({report.record_type})",
            style="blue",
        )
    )
    if report.chain:
        console.print(_chain_table(report.chain))
    else:
        console.print("  [dim]No chain data available.[/dim]")


def print_leaf(report: DNSSECReport) -> None:
    """Render the leaf record validation result.

    :param report: The full validation report.
    :type report: ~chainvalidator.models.DNSSECReport
    """
    leaf = report.leaf
    console.print(
        Panel(
            f"[bold]Leaf Record[/bold] – {report.domain} {report.record_type}",
            style="blue",
        )
    )

    if leaf is None:
        console.print("  [dim]Chain validation did not reach the leaf record.[/dim]")
        return

    if leaf.cname_chain:
        console.print(
            f"  [dim]CNAME chain:[/dim] {report.domain}"
            + "".join(f"  →  {c}" for c in leaf.cname_chain)
        )

    if leaf.records:
        tbl = Table(show_header=False, box=None, padding=(0, 1))
        tbl.add_column("RR", style="dim", no_wrap=True)
        tbl.add_column("Value")
        for r in leaf.records:
            tbl.add_row(f"{leaf.qname} IN {leaf.record_type}", r)
        console.print(tbl)
    elif leaf.nxdomain:
        if leaf.status is Status.SECURE:
            console.print(
                f"  [green]✔[/green]  [bold]{leaf.qname}[/bold] does not exist "
                f"(secure NXDOMAIN — denial of existence proof validated)"
            )
        else:
            console.print(
                f"  [yellow]⚠[/yellow]  [bold]{leaf.qname}[/bold] does not exist "
                f"(NXDOMAIN — no signed denial proof available)"
            )
    elif leaf.nodata:
        if leaf.status is Status.SECURE:
            console.print(
                f"  [green]✔[/green]  [bold]{leaf.qname}[/bold] has no "
                f"{leaf.record_type} records (secure NODATA — NSEC3 proof validated)"
            )
    else:
        console.print(
            f"  [dim]No {leaf.record_type} records found (NODATA or NXDOMAIN).[/dim]"
        )

    if leaf.rrsig_used:
        rrsig_line = f"RRSIG validated with DNSKEY={leaf.rrsig_used}"
        if leaf.rrsig_expires:
            rrsig_line += f"  (expires {leaf.rrsig_expires})"
        console.print(f"  [green]{rrsig_line}[/green]")

    for note in leaf.notes:
        console.print(f"  [cyan]ℹ[/cyan]  {note}")
    for warn in leaf.warnings:
        console.print(f"  [yellow]⚠[/yellow]  {warn}")
    for err in leaf.errors:
        console.print(f"  [red]✘[/red]  {err}")


def print_verdict(report: DNSSECReport) -> None:
    """Render the final verdict panel.

    :param report: The full validation report.
    :type report: ~chainvalidator.models.DNSSECReport
    """
    style = _status_panel_style(report.status)

    lines: list[str] = []
    if report.status is Status.SECURE:
        lines.append(
            f"✔  [bold green]{report.domain}[/bold green] — "
            "full chain of trust validated successfully."
        )
    elif report.status is Status.INSECURE:
        lines.append(
            f"⚠   [bold yellow]{report.domain}[/bold yellow] — "
            "chain is NOT fully anchored to the root trust anchor."
        )
        for w in report.warnings:
            lines.append(f"    [yellow]•[/yellow] {w}")
    else:
        lines.append(
            f"✘  [bold red]{report.domain}[/bold red] — DNSSEC validation FAILED."
        )
        for e in report.errors:
            lines.append(f"    [red]•[/red] {e}")

    console.print(Panel("\n".join(lines), title="Verdict", style=style))


# ---------------------------------------------------------------------------
# Full report
# ---------------------------------------------------------------------------


def print_full_report(report: DNSSECReport) -> None:
    """Render the complete :class:`~chainvalidator.models.DNSSECReport` to the terminal.

    Sections are printed in order: header rule, trust anchor, chain table,
    leaf record, verdict.

    :param report: The fully populated validation report.
    :type report: ~chainvalidator.models.DNSSECReport
    """
    console.rule(
        f"[bold cyan]DNSSEC Validation Report: {report.domain} ({report.record_type})[/bold cyan]"
    )
    print_trust_anchor(report)
    print_chain(report)
    print_leaf(report)
    print_verdict(report)
    console.rule("[dim]End of Report[/dim]")
