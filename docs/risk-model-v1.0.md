# QRYPTON Risk Model 1.0.0

This is QRYPTON's deterministic classification policy. It is an engineering
taxonomy, not a standards body's approval list. An unmatched algorithm or
missing parameter stays `UNKNOWN`; the implementation does not infer weakness
from missing evidence.

## Cryptographic risk

The classifier evaluates the observed canonical name, family, lifecycle status,
key size, and the observed block-cipher `mode` parameter, in this order:

| Risk | Rule |
| --- | --- |
| `CRITICAL` | Name matches MD2/MD4/MD5, DES/3DES, RC2/RC4, or SHA-0; RSA is below 1024 bits; AES is below 128 bits. |
| `HIGH` | Lifecycle is deprecated/disallowed; ECB mode is observed; SHA-1 is named; RSA is below 2048 bits; elliptic-curve size is below P-256. |
| `MEDIUM` | SHA-224; RSA from 2048 through 3071 bits; AES-128; P-256; Ed25519 or X25519. |
| `LOW` | Recognized SHA-2/SHA-3 digest, AES of at least 192 bits, RSA of at least 3072 bits, P-384/P-521, or a named PQC algorithm. |
| `UNKNOWN` | Algorithm is unobserved, required strength parameters are missing, or the algorithm is not covered by this version. |

Broken-name rules take precedence over lifecycle status. Deprecated/disallowed
status and an observed ECB mode take precedence over ordinary strength bands.
The listed rules and aliases are implemented by `classify_finding` in
`src/qrypton/risk/taxonomy.py`; changes require a new ruleset version.

## Quantum risk and Mosca applicability

- Named ML-KEM, ML-DSA, SLH-DSA, Kyber, Dilithium, SPHINCS, or Falcon algorithms
  are quantum risk `LOW`; Mosca is `NOT_APPLICABLE`.
- Classical RSA, DSA, DH, ECC, ECDSA, ECDH, Ed25519, and X25519 public-key
  families are quantum risk `HIGH`; Mosca applies.
- Symmetric cipher, hash, MAC, and KDF families are quantum risk `MEDIUM`;
  Mosca is `NOT_APPLICABLE`.
- Unknown applicability remains `UNKNOWN` and has no Mosca urgency calculation.

For an applicable finding, required time is `X + Y`. If `X + Y > Z`, Mosca
urgency is `CRITICAL`; equality is `HIGH`; below Z is `MEDIUM` when
`(X + Y) / Z >= 0.5`, otherwise `LOW`. With Z=0, positive `X + Y` is
`CRITICAL`, while `X + Y=0` is `HIGH`. These are temporal urgency labels, not
final-priority labels.

X/Y resolution is finding override, then asset business context, then the run
scenario. Z is run-scenario scoped. Each persisted evaluation records values
and sources, including for findings where Mosca is not applicable.

## Business impact and final priority

Observed criticality maps to the matching tier. Observed data classification
maps public/internal/confidential/restricted to LOW/MEDIUM/HIGH/CRITICAL.
Observed internet exposure adds HIGH when true. A regulated scope adds HIGH
when business-context evidence is present. The highest evidenced category is
the business-impact dimension; no observed inputs means `UNKNOWN`.

Final priority is the highest known crypto or quantum tier, with business impact
alone capped at MEDIUM. If that technical tier is already HIGH and business
impact is HIGH or CRITICAL, priority increases one tier, capped at CRITICAL.
Confidence and Mosca urgency do not enter this calculation. Its ordinal score
is 25 points per priority tier; the categorical priority remains authoritative.
