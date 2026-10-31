"""PkgSentinel: static, explainable malware scanning for npm and PyPI packages.

The Python package and CLI are named `harmonica` (after the team that builds it).
"""

from .scanner import Finding, run_scanner

__version__ = "0.1.0"
__all__ = ["Finding", "run_scanner", "__version__"]
