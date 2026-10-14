"""Closed vocabularies used by QRYPTON contracts."""

from enum import StrEnum


class ObservationState(StrEnum):
    OBSERVED = "observed"
    NOT_OBSERVED = "not_observed"
    UNKNOWN = "unknown"
    CONFIRMED_ABSENT = "confirmed_absent"


class AssetKind(StrEnum):
    APPLICATION = "application"
    SERVICE = "service"
    HOST = "host"
    REPOSITORY = "repository"
    CONTAINER_IMAGE = "container_image"
    BINARY = "binary"
    LIBRARY = "library"
    DATASTORE = "datastore"
    OTHER = "other"


class ScanTargetKind(StrEnum):
    SOURCE_TREE = "source_tree"
    GIT_ARCHIVE = "git_archive"
    ELF = "elf"
    PE = "pe"
    MACH_O = "mach_o"
    OCI_IMAGE = "oci_image"
    DOCKER_ARCHIVE = "docker_archive"
    FILE = "file"


class EvidenceKind(StrEnum):
    SOURCE_AST = "source_ast"
    SOURCE_LEXICAL = "source_lexical"
    BINARY_SYMBOL = "binary_symbol"
    BINARY_STRING = "binary_string"
    BINARY_IMPORT = "binary_import"
    IMAGE_MANIFEST = "image_manifest"
    IMAGE_LAYER = "image_layer"
    CERTIFICATE = "certificate"
    CONFIGURATION = "configuration"
    PACKAGE_METADATA = "package_metadata"
    USER_ASSERTION = "user_assertion"


class EvidenceSurface(StrEnum):
    """Discovery surface that produced a canonical evidence record."""

    SOURCE = "source"
    BINARY = "binary"
    LIBRARY = "library"
    CONTAINER = "container"
    KMS = "kms"
    API = "api"
    UNKNOWN = "unknown"


class EvidenceCollectionMode(StrEnum):
    """How QRYPTON obtained evidence; this must never overstate live access."""

    STATIC_ARTIFACT = "static_artifact"
    STATIC_IDENTIFIER = "static_identifier"
    AUTHENTICATED_API = "authenticated_api"
    UNKNOWN = "unknown"


class AlgorithmFamily(StrEnum):
    SYMMETRIC_CIPHER = "symmetric_cipher"
    ASYMMETRIC_ENCRYPTION = "asymmetric_encryption"
    SIGNATURE = "signature"
    HASH = "hash"
    MAC = "mac"
    KDF = "kdf"
    KEY_AGREEMENT = "key_agreement"
    RNG = "rng"
    PROTOCOL = "protocol"
    UNKNOWN = "unknown"


class AlgorithmStatus(StrEnum):
    APPROVED = "approved"
    DEPRECATED = "deprecated"
    DISALLOWED = "disallowed"
    LEGACY = "legacy"
    UNKNOWN = "unknown"


class AlgorithmIdentificationStatus(StrEnum):
    IDENTIFIED = "identified"
    PARTIALLY_IDENTIFIED = "partially_identified"
    UNKNOWN = "unknown"


class KeyKind(StrEnum):
    SYMMETRIC = "symmetric"
    PUBLIC = "public"
    PRIVATE = "private"
    SECRET = "secret"
    UNKNOWN = "unknown"


class ProtocolLayer(StrEnum):
    TRANSPORT = "transport"
    APPLICATION = "application"
    TUNNEL = "tunnel"
    MESSAGING = "messaging"
    UNKNOWN = "unknown"


class Criticality(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class RiskLevel(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class MoscaUrgency(StrEnum):
    """Temporal migration urgency; values intentionally differ from risk levels by type."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"


class RecommendationKind(StrEnum):
    INVENTORY = "inventory"
    REMEDIATION = "remediation"
    MIGRATION = "migration"
    COMPENSATING_CONTROL = "compensating_control"
    VALIDATION = "validation"


class RunStatus(StrEnum):
    PENDING = "pending"
    SCANNING = "scanning"
    NORMALIZING = "normalizing"
    CORRELATING = "correlating"
    ASSESSING = "assessing"
    RECOMMENDING = "recommending"
    EXPORTING = "exporting"
    PERSISTING = "persisting"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
