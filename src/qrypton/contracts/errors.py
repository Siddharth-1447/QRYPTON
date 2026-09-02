"""Domain-specific errors."""


class QryptonContractError(ValueError):
    """Raised when a contract invariant cannot be satisfied."""


class IdDerivationError(QryptonContractError):
    """Raised when deterministic-ID input is invalid."""
