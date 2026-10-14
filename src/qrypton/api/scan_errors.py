"""Public scan failure messages, independent of exception text and target secrets."""

from __future__ import annotations

import urllib.error

_MESSAGES = {
    "target_resolution_failed": (
        "Could not acquire the target. Check the repository URL and branch, "
        "or verify the file exists on the scan server. "
        "Private repositories require an uploaded archive."
    ),
    "target_not_found": (
        "Repository or branch was not found. Check the URL and exact branch name. "
        "For a private repository, upload a source archive."
    ),
    "target_access_denied": (
        "The scan service cannot access this target. Check access permissions "
        "or upload a source archive."
    ),
    "target_service_unavailable": (
        "The repository host is unavailable or rate-limiting requests. "
        "Retry later or upload a source archive."
    ),
    "target_acquisition_timeout": (
        "Target acquisition timed out. Check the scan server's connection "
        "or upload a smaller source archive."
    ),
    "target_network_error": (
        "The scan server could not connect securely to the repository host. "
        "Check its network and certificate configuration, or upload a source archive."
    ),
    "target_file_missing": (
        "Target file was not found on the scan server. "
        "Upload it again or correct the server-local path."
    ),
    "scan_configuration_failed": (
        "Scan configuration failed. Review the scan settings and timeline values."
    ),
    "scan_timeout": "Scan exceeded its execution limit. Reduce the target scope and try again.",
    "scan_submission_failed": "No scan worker was available. Try submitting the scan again.",
    "unexpected_worker_error": (
        "The scan worker failed unexpectedly. Check server logs using the run ID."
    ),
}


def public_failure_message(error_code: str, stage: str | None = None) -> str:
    """Never return stored exception messages, which may contain sensitive locators."""
    if error_code in _MESSAGES:
        return _MESSAGES[error_code]
    if stage == "resolve":
        return _MESSAGES["target_resolution_failed"]
    return "Scan did not complete. Check server logs using the run ID, then retry."


def resolution_failure_code(error: Exception) -> str:
    """Classify bounded cause chains, including acquisition's wrapped URL errors."""
    current: BaseException | None = error
    causes: list[BaseException] = []
    while current is not None and len(causes) < 12:
        causes.append(current)
        reason = getattr(current, "reason", None)
        current = current.__cause__ or (reason if isinstance(reason, BaseException) else None)
    for cause in reversed(causes):
        if isinstance(cause, urllib.error.HTTPError):
            if cause.code == 404:
                return "target_not_found"
            if cause.code in {401, 403}:
                return "target_access_denied"
            if cause.code == 429 or cause.code >= 500:
                return "target_service_unavailable"
        elif isinstance(cause, TimeoutError):
            return "target_acquisition_timeout"
        elif isinstance(cause, PermissionError):
            return "target_access_denied"
        elif isinstance(cause, FileNotFoundError):
            return "target_file_missing"
        elif isinstance(cause, urllib.error.URLError):
            return "target_network_error"
    return "target_resolution_failed"
