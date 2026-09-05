"""Domain-specific errors."""


class QryptonContractError(ValueError):
    """Raised when a contract invariant cannot be satisfied."""


class IdDerivationError(QryptonContractError):
    """Raised when deterministic-ID input is invalid."""


class CBOMExportError(QryptonContractError):
    """Raised when QRYPTON cannot safely construct a CBOM."""


class CBOMValidationError(CBOMExportError):
    """Raised when a constructed document violates CycloneDX 1.6."""
