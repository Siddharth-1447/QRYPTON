# QRYPTON normalization and correlation model 1.0

## Canonical evidence contract

Every scanner emits a bounded raw observation that is normalized into the same
`Evidence` and `CryptoFinding` contracts. An `Evidence` record always retains:

- its scanner provenance and source digest;
- `surface` (`source`, `binary`, `library`, `container`, `kms`, `api`, or
  `unknown`);
- `collection_mode` (`static_artifact`, `static_identifier`,
  `authenticated_api`, or `unknown`);
- a bounded location anchor and semantic attributes; and
- explicit limitations when the collection path could not observe the target.

`CryptoFinding` represents one cryptographic usage or one explicitly scoped
library, protocol, certificate, or key-material observation. A repository root
is the owning asset for a scan; it is never evidence that its usages are one
finding. Finding count therefore comes from distinct canonical usage records,
not from asset count.

## Correlation rule

Normalizers remove byte-for-byte repeated observations by deterministic evidence
ID. The correlation engine can merge candidate findings only when all of the
following agree:

1. tenant, asset, and scan target scope;
2. finding category, algorithm parameters and identity state, crypto role, and
   protocol/library/key-material identity where present; and
3. an evidence usage anchor: location plus any observed module, service,
   package, layer, format, subject, or role context.

An unresolved evidence ID is a unique anchor. This deliberately retains
unlocatable candidates as separate findings instead of merging on an algorithm
or library label.

Valid merges include complementary observations of the same source usage, such
as AST and lexical evidence for the same algorithm call at the same location.
All participating evidence IDs remain on the merged finding. The lead finding's
confidence remains unchanged; correlated evidence never raises it implicitly.

The following merges are prohibited:

- two source calls at different files, lines, symbols, modules, or services;
- a source usage and a binary symbol without a shared canonical usage anchor;
- two dependencies merely because they have the same library name or version;
- protocol, library, certificate, key-material, and algorithm findings merely
  because their labels overlap; and
- candidates from different assets or scan targets.

## Surface semantics

Source, binary, dependency/library, and supplied container artifacts are
`static_artifact` evidence. They preserve their scanner provenance and location
without claiming runtime execution.

KMS discovery currently supports static key identifiers and supplied descriptor
documents only. It emits `surface=kms` and `collection_mode=static_identifier`
with an explicit limitation that no authenticated cloud-provider API call was
made. QRYPTON does not currently implement authenticated AWS, Azure, or GCP KMS
API discovery; it must not label any KMS record as `authenticated_api` until
that collector and its credential, authorization, and response provenance are
implemented.
