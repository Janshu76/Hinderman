"""Compatibility imports for callers using the original gateway namespace."""

from detectors.credentials import detect_credentials, shannon_entropy

__all__ = ["detect_credentials", "shannon_entropy"]
