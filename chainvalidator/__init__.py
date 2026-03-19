"""chainvalidator – DNSSEC Chain-of-Trust Validator.

Public API::

    from chainvalidator.assessor import assess
    from chainvalidator.models   import DNSSECReport, Status

Diagnostic output is emitted via the ``"chainvalidator"`` :mod:`logging`
logger.  No handler is attached at import time so library users retain full
control.  The CLI never configures this logger — it uses Rich for output::

    import logging
    logging.getLogger("chainvalidator").setLevel(logging.DEBUG)
    report = assess("example.com")
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("chainvalidator")
except PackageNotFoundError:  # pragma: no cover
    __version__ = "0.1.0"

# NullHandler so library users who have not configured logging
# do not see "No handler found" warnings (PEP 3118 / logging HOWTO).
import logging as _logging

_logging.getLogger("chainvalidator").addHandler(_logging.NullHandler())
del _logging

__all__ = ["__version__"]
