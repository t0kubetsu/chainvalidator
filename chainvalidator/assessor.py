"""High-level assessment API for chainvalidator.

Typical usage::

    from chainvalidator.assessor import assess

    report = assess("example.com", record_type="A")
    # report.status             → Status.SECURE | INSECURE | BOGUS
    # report.chain              → list[ChainLink]
    # report.leaf               → LeafResult | None
    # report.trust_anchor_keys  → list[str]
    # report.errors             → list[str]
    # report.warnings           → list[str]

Diagnostic output is emitted via the ``"chainvalidator"`` :mod:`logging`
logger.  Attach a handler and set the desired level before calling to
capture it:

.. code-block:: python

    import logging
    logging.getLogger("chainvalidator").setLevel(logging.DEBUG)
    report = assess("example.com")
"""

from __future__ import annotations

from typing import Callable

from chainvalidator.checker import DNSSECChecker
from chainvalidator.constants import DNS_TIMEOUT
from chainvalidator.models import DNSSECReport


def assess(
    domain: str,
    *,
    record_type: str = "A",
    timeout: float = DNS_TIMEOUT,
    progress_cb: Callable[[str], None] | None = None,
) -> DNSSECReport:
    """Run the full DNSSEC chain-of-trust validation for *domain*.

    This is the only public entry-point for programmatic use.  It returns a
    :class:`~chainvalidator.models.DNSSECReport` with per-zone chain links,
    the leaf record result, and an overall
    :class:`~chainvalidator.models.Status`.

    Diagnostic output is emitted via the ``"chainvalidator"`` :mod:`logging`
    logger at four levels:

    * ``DEBUG``   — per-query detail: NS selection, keytag listings, RRSIG expiry.
    * ``INFO``    — chain milestones: zone headers, DS/DNSKEY matches, final verdict.
    * ``WARNING`` — insecure delegations, unsigned zones, NXDOMAIN.
    * ``ERROR``   — hard validation failures (bogus chain).

    Attach a handler before calling to capture these messages::

        import logging
        logging.getLogger("chainvalidator").setLevel(logging.INFO)

    :param domain: Domain name to validate, e.g. ``"example.com"``.
    :type domain: str
    :param record_type: DNS record type to validate at the leaf
        (default ``"A"``).
    :type record_type: str
    :param timeout: Per-query UDP/TCP timeout in seconds
        (default :data:`~chainvalidator.constants.DNS_TIMEOUT`).
    :type timeout: float
    :param progress_cb: Optional callable invoked with a short status string
        before each major validation step.  Used by the CLI to drive a Rich
        progress spinner; ignored when ``None``.
    :type progress_cb: callable or None
    :returns: Fully populated :class:`~chainvalidator.models.DNSSECReport`.
    :rtype: ~chainvalidator.models.DNSSECReport
    :raises ValueError: If *domain* or *record_type* is syntactically invalid.
    """
    if progress_cb:
        progress_cb(f"Resolving zone hierarchy for {domain} …")
    checker = DNSSECChecker(domain, record_type=record_type, timeout=timeout)

    if progress_cb:
        progress_cb("Fetching IANA trust anchor …")
    checker.check()

    return checker.report
