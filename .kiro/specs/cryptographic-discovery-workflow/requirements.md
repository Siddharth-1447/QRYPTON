# Cryptographic Discovery Workflow - Requirements

## Overview

QRYPTON/ECDAT is an enterprise cryptographic intelligence platform that performs static inspection of cryptographic assets across multiple target types, assesses quantum risk, applies business context, and generates actionable migration roadmaps for post-quantum cryptography (PQC) readiness.

## Core Principle

**STATIC INSPECTION ONLY**: QRYPTON must NEVER execute, deploy, modify, or run any target being analyzed.

## Feature Summary

Transform QRYPTON from a basic cryptographic scanner into a comprehensive cryptographic intelligence platform that:
1. Discovers cryptographic assets across 6 target types
2. Classifies findings with context (production/test/dependency)
3. Generates standardized CBOM (Cryptographic Bill of Materials)
4. Performs quantum risk analysis using MOSCA model
5. Applies business risk scoring
6. Provides actionable PQC/hybrid recommendations
7. Generates prioritized migration roadmaps
8. Delivers evidence-based, explainable results

---

## Implementation Phases

The 19 main problem areas will be addressed in **7 phases of 3 problems each** (with Phase 7 having 1 problem):

### Phase 1: Foundation (Discovery & Classification)
**Problems 1-3**: Target Support, Discovery Engine, Context Classification
- Problem 1: Multi-target type discovery (source repos, archives, binaries, manifests, containers, KMS)
- Problem 2: Normalized finding model with consistent schema across all target types
- Problem 3: Context classification to distinguish production from test/dependency/documentation usage

### Phase 2: Intelligence & Risk (CBOM, Quantum, MOSCA)
**Problems 4-6**: CBOM, Quantum Risk, MOSCA Model
- Problem 4: Standardized CBOM generation with complete metadata
- Problem 5: Quantum vulnerability assessment with HNDL detection
- Problem 6: MOSCA risk modeling (X + Y > Z) for migration urgency

### Phase 3: Prioritization & Visualization (Risk Scoring, Dashboard, Heatmap)
**Problems 7-9**: Business Risk, Dashboard, Risk Heatmap
- Problem 7: Business-contextualized risk scoring and prioritization
- Problem 8: Executive risk dashboard with drill-down capabilities
- Problem 9: Visual risk heatmap (MOSCA urgency vs business criticality)

### Phase 4: Action Planning (MOSCA Matrix, PQC Recommendations, Roadmap)
**Problems 10-12**: Timeline Viz, PQC Guidance, Migration Roadmap
- Problem 10: MOSCA urgency matrix visualization
- Problem 11: NIST-aligned PQC/hybrid recommendation engine
- Problem 12: Phased, prioritized migration roadmap generation

### Phase 5: Developer Experience (Remediation, Evidence, Summary)
**Problems 13-15**: Actionable Fixes, Explainability, Executive Reporting
- Problem 13: Actionable remediation guidance for developers
- Problem 14: Evidence-based explainability for all findings and risk scores
- Problem 15: Executive summary report generation

### Phase 6: Analysis & Navigation (Search, History, Differentiation)
**Problems 16-18**: Filtering, Temporal Analysis, Platform Identity
- Problem 16: Comprehensive search, filter, and drill-down capabilities
- Problem 17: Scan history with temporal comparison and progress tracking
- Problem 18: Platform differentiation (intelligence platform vs basic scanner)

### Phase 7: User Experience (UX)
**Problem 19**: Comprehensive Dashboard UX
- Problem 19: Professional post-scan dashboard integrating all capabilities

---

## 1. Target Type Support

### 1.1 Source Repository

**User Story**: As a security engineer, I want to scan a source repository URL so that I can discover all cryptographic usage, imports, dependencies, and configurations without executing any code.

**Acceptance Criteria**:
- [ ] 1.1.1 Accept repository URL and branch/tag reference
- [ ] 1.1.2 Statically inspect source code files for crypto API usage
- [ ] 1.1.3 Identify cryptographic imports and library usage
- [ ] 1.1.4 Analyze configuration files for crypto settings
- [ ] 1.1.5 Parse build files and dependency declarations
- [ ] 1.1.6 Detect certificate and key references
- [ ] 1.1.7 Distinguish production code from test code
- [ ] 1.1.8 Identify documentation/example crypto usage
- [ ] 1.1.9 Never execute or modify repository contents

### 1.2 Source Archive

**User Story**: As a developer, I want to upload a source archive (.zip, .tar.gz) for cryptographic analysis so that I can assess crypto usage in offline or proprietary codebases.

**Acceptance Criteria**:
- [ ] 1.2.1 Accept uploaded source archives
- [ ] 1.2.2 Extract and analyze archive contents statically
- [ ] 1.2.3 Perform same crypto discovery as source repository
- [ ] 1.2.4 Never execute extracted files
- [ ] 1.2.5 Support common archive formats (zip, tar.gz, tar.bz2)

### 1.3 Binary

**User Story**: As a security analyst, I want to inspect compiled binaries for cryptographic capabilities so that I can assess third-party or legacy applications without source access.

**Acceptance Criteria**:
- [ ] 1.3.1 Accept binary/executable files
- [ ] 1.3.2 Identify embedded cryptographic algorithms
- [ ] 1.3.3 Detect crypto libraries and symbols
- [ ] 1.3.4 Find embedded certificates and keys
- [ ] 1.3.5 Identify TLS/crypto capabilities
- [ ] 1.3.6 Distinguish confirmed from inferred findings
- [ ] 1.3.7 Never execute the binary

### 1.4 Dependency Manifest

**User Story**: As a DevOps engineer, I want to analyze dependency manifests (package.json, requirements.txt, pom.xml) so that I can understand transitive cryptographic dependencies.

**Acceptance Criteria**:
- [ ] 1.4.1 Parse common manifest formats
- [ ] 1.4.2 Identify direct crypto dependencies
- [ ] 1.4.3 Resolve transitive crypto dependencies
- [ ] 1.4.4 Determine library versions
- [ ] 1.4.5 Map known cryptographic capabilities per library
- [ ] 1.4.6 Distinguish "library exists" from "application invokes crypto"
- [ ] 1.4.7 Support multiple package ecosystems (npm, pip, maven, cargo)

### 1.5 Container Image

**User Story**: As a cloud security engineer, I want to inspect container images for cryptographic assets so that I can assess containerized applications without running them.

**Acceptance Criteria**:
- [ ] 1.5.1 Inspect container metadata and layers
- [ ] 1.5.2 Identify crypto libraries in base images
- [ ] 1.5.3 Detect OpenSSL/LibreSSL/BoringSSL versions
- [ ] 1.5.4 Find application crypto dependencies
- [ ] 1.5.5 Locate certificates and key references
- [ ] 1.5.6 Analyze TLS configuration
- [ ] 1.5.7 Never execute or start the container

### 1.6 Cloud KMS

**User Story**: As a cloud architect, I want to inventory managed keys from cloud KMS services so that I can assess quantum readiness of cloud-managed cryptographic keys.

**Acceptance Criteria**:
- [ ] 1.6.1 Connect to cloud KMS APIs (AWS KMS, Azure Key Vault, GCP KMS)
- [ ] 1.6.2 Retrieve key metadata (not secret material)
- [ ] 1.6.3 Capture key type, algorithm, size
- [ ] 1.6.4 Record usage purpose and rotation config
- [ ] 1.6.5 Identify quantum-vulnerable keys
- [ ] 1.6.6 Map keys to applications/services
- [ ] 1.6.7 Never retrieve private key material

---

## 2. Cryptographic Discovery Engine

### 2.1 Normalized Finding Model

**User Story**: As a data analyst, I want all cryptographic findings normalized into a consistent schema so that I can aggregate and analyze findings across different target types.

**Acceptance Criteria**:
- [ ] 2.1.1 Create unique asset ID for each finding
- [ ] 2.1.2 Capture target type and target identifier
- [ ] 2.1.3 Record artifact type (source file, binary, config, etc.)
- [ ] 2.1.4 Store precise location (file path, line number, symbol)
- [ ] 2.1.5 Identify cryptographic algorithm and family
- [ ] 2.1.6 Capture operation type (encryption, signing, hashing, etc.)
- [ ] 2.1.7 Record mode, key size, and parameters
- [ ] 2.1.8 Identify crypto library/provider and version
- [ ] 2.1.9 Assign confidence level (0.0-1.0)
- [ ] 2.1.10 Store raw evidence supporting the finding

### 2.2 Supported Operations

**Acceptance Criteria**:
- [ ] 2.2.1 Detect encryption operations
- [ ] 2.2.2 Detect decryption operations
- [ ] 2.2.3 Detect signing operations
- [ ] 2.2.4 Detect verification operations
- [ ] 2.2.5 Detect key generation
- [ ] 2.2.6 Detect key exchange (ECDH, DH)
- [ ] 2.2.7 Detect key derivation (PBKDF2, HKDF)
- [ ] 2.2.8 Detect hashing operations
- [ ] 2.2.9 Detect MAC operations
- [ ] 2.2.10 Detect random number generation
- [ ] 2.2.11 Detect TLS/certificate operations

---

## 3. Context Classification

### 3.1 Usage Context Determination

**User Story**: As a security engineer, I want each cryptographic finding classified by context (production, test, dependency, documentation) so that I can prioritize real security-sensitive usage.

**Acceptance Criteria**:
- [ ] 3.1.1 Classify as production usage with evidence
- [ ] 3.1.2 Classify as test usage (in test directories/files)
- [ ] 3.1.3 Classify as documentation/example
- [ ] 3.1.4 Classify as dependency capability only
- [ ] 3.1.5 Classify as library API exposure
- [ ] 3.1.6 Classify as configuration reference
- [ ] 3.1.7 Support multiple context tags per finding
- [ ] 3.1.8 Provide classification rationale
- [ ] 3.1.9 Distinguish test vectors from production crypto

**Examples**:
- RSA in test_crypto.py → Test-only → Low priority
- RSA API exposed by imported library → Capability → Inventory only
- RSA used for JWT signing in auth service → Production → High priority

---

## 4. CBOM Generation

### 4.1 Cryptographic Bill of Materials

**User Story**: As a compliance officer, I want a standardized CBOM export so that I can report cryptographic inventory to auditors and stakeholders in a machine-readable format.

**Acceptance Criteria**:
- [ ] 4.1.1 Generate JSON CBOM for all findings
- [ ] 4.1.2 Include asset ID, target, artifact details
- [ ] 4.1.3 Include algorithm, operation, mode, key size
- [ ] 4.1.4 Include library/provider and version
- [ ] 4.1.5 Include usage context classification
- [ ] 4.1.6 Include business metadata (criticality, environment)
- [ ] 4.1.7 Include quantum status
- [ ] 4.1.8 Include MOSCA values (X, Y, Z, margin)
- [ ] 4.1.9 Include risk score and urgency
- [ ] 4.1.10 Include recommended replacement
- [ ] 4.1.11 Include migration priority and strategy
- [ ] 4.1.12 Mark unknown/indeterminate values explicitly
- [ ] 4.1.13 Support CycloneDX CBOM standard where applicable

---

## 5. Quantum Risk Analysis

### 5.1 Quantum Vulnerability Assessment

**User Story**: As a cryptographic expert, I want each finding assessed for quantum vulnerability so that I can understand which algorithms are at risk from quantum computers.

**Acceptance Criteria**:
- [ ] 5.1.1 Classify as quantum-safe (AES, SHA-3, ML-KEM, ML-DSA)
- [ ] 5.1.2 Classify as quantum-vulnerable (RSA, ECC, DSA, DH)
- [ ] 5.1.3 Classify as conditionally vulnerable (AES-128, SHA-256)
- [ ] 5.1.4 Handle symmetric crypto appropriately (key-size increase, not broken)
- [ ] 5.1.5 Handle hash functions appropriately (collision resistance)
- [ ] 5.1.6 Identify HNDL (Harvest Now, Decrypt Later) exposure
- [ ] 5.1.7 Provide quantum risk rationale

### 5.2 HNDL Exposure Detection

**User Story**: As a CISO, I want to identify cryptographic assets with HNDL exposure so that I can prioritize protection of long-lived sensitive data.

**Acceptance Criteria**:
- [ ] 5.2.1 Identify quantum-vulnerable asymmetric crypto
- [ ] 5.2.2 Combine with data lifetime (X)
- [ ] 5.2.3 Combine with data sensitivity
- [ ] 5.2.4 Flag high-sensitivity + long-lifetime + quantum-vulnerable
- [ ] 5.2.5 Provide HNDL risk explanation

---

## 6. MOSCA Risk Model

### 6.1 MOSCA Calculation

**User Story**: As a migration planner, I want each asset evaluated using the MOSCA model (X + Y > Z) so that I can understand migration urgency based on timelines.

**Acceptance Criteria**:
- [ ] 6.1.1 Accept X (data lifetime) from business context
- [ ] 6.1.2 Accept Y (migration time) from complexity assessment
- [ ] 6.1.3 Accept Z (CRQC horizon) from organizational config
- [ ] 6.1.4 Calculate X + Y
- [ ] 6.1.5 Calculate margin: Z - (X + Y)
- [ ] 6.1.6 Determine urgency: critical if X + Y > Z
- [ ] 6.1.7 Store all MOSCA values with finding
- [ ] 6.1.8 Provide MOSCA explanation (not a prediction, a planning model)

### 6.2 MOSCA Urgency Classification

**Acceptance Criteria**:
- [ ] 6.2.1 Classify as "critical" if X + Y > Z
- [ ] 6.2.2 Classify as "high" if X + Y close to Z (within 1 year)
- [ ] 6.2.3 Classify as "medium" if margin is 1-3 years
- [ ] 6.2.4 Classify as "low" if margin is > 3 years
- [ ] 6.2.5 Support configurable thresholds

---

## 7. Business Risk Scoring

### 7.1 Contextual Risk Assessment

**User Story**: As a risk manager, I want cryptographic risk combined with business context so that I can prioritize based on actual business impact, not just technical vulnerability.

**Acceptance Criteria**:
- [ ] 7.1.1 Combine quantum vulnerability with business criticality
- [ ] 7.1.2 Factor in data sensitivity classification
- [ ] 7.1.3 Factor in data lifetime
- [ ] 7.1.4 Factor in internet exposure (public vs internal)
- [ ] 7.1.5 Factor in environment (production vs dev)
- [ ] 7.1.6 Factor in authentication/signing importance
- [ ] 7.1.7 Factor in regulatory/compliance requirements
- [ ] 7.1.8 Factor in migration complexity
- [ ] 7.1.9 Generate risk score (0-100 or similar scale)
- [ ] 7.1.10 Provide risk score rationale

### 7.2 Risk Prioritization

**User Story**: As an application owner, I want assets prioritized by combined business and cryptographic risk so that I focus on the most critical migrations first.

**Acceptance Criteria**:
- [ ] 7.2.1 Rank findings by risk score
- [ ] 7.2.2 Support filtering by risk level (critical, high, medium, low)
- [ ] 7.2.3 Separate critical from informational findings
- [ ] 7.2.4 Avoid undifferentiated alert fatigue

**Examples**:
- RSA-2048, internal test, low criticality, short-lived → Low priority
- RSA-2048, internet-facing auth, critical service, long-lived identity → Critical priority

---

## 8. Risk Dashboard

### 8.1 Executive Posture View

**User Story**: As an executive, I want a high-level cryptographic posture dashboard so that I can understand organizational quantum readiness at a glance.

**Acceptance Criteria**:
- [ ] 8.1.1 Display total cryptographic assets discovered
- [ ] 8.1.2 Display quantum-vulnerable asset count
- [ ] 8.1.3 Display quantum-safe asset count
- [ ] 8.1.4 Display high-risk asset count
- [ ] 8.1.5 Display critical asset count
- [ ] 8.1.6 Display HNDL-exposed asset count
- [ ] 8.1.7 Display assets requiring migration
- [ ] 8.1.8 Display assets requiring validation
- [ ] 8.1.9 Show policy pass/fail status
- [ ] 8.1.10 Show scan status and coverage

### 8.2 Drill-Down Views

**Acceptance Criteria**:
- [ ] 8.2.1 Show findings by algorithm
- [ ] 8.2.2 Show findings by crypto library
- [ ] 8.2.3 Show findings by target type
- [ ] 8.2.4 Show findings by business criticality
- [ ] 8.2.5 Show findings by environment
- [ ] 8.2.6 Show findings by application/service
- [ ] 8.2.7 Show findings by quantum status
- [ ] 8.2.8 Support navigation from aggregate to detail

---

## 9. Cryptographic Risk Heatmap

### 9.1 Visual Risk Matrix

**User Story**: As a security architect, I want a risk heatmap showing MOSCA urgency vs business criticality so that I can visually identify the highest-priority migration targets.

**Acceptance Criteria**:
- [ ] 9.1.1 Display 4x4 matrix (or configurable dimensions)
- [ ] 9.1.2 X-axis: Business criticality (low, medium, high, critical)
- [ ] 9.1.3 Y-axis: MOSCA urgency (low, medium, high, critical)
- [ ] 9.1.4 Each cell shows finding count
- [ ] 9.1.5 Cell colors indicate severity
- [ ] 9.1.6 Clicking a cell filters inventory to matching findings
- [ ] 9.1.7 Provide clear legend and axes labels

---

## 10. MOSCA Urgency Matrix

### 10.1 Timeline Visualization

**User Story**: As a program manager, I want a dedicated MOSCA visualization showing X, Y, Z relationships so that I can communicate migration urgency to stakeholders.

**Acceptance Criteria**:
- [ ] 10.1.1 Visualize X (data lifetime)
- [ ] 10.1.2 Visualize Y (migration time)
- [ ] 10.1.3 Visualize Z (CRQC horizon)
- [ ] 10.1.4 Highlight assets where X + Y > Z
- [ ] 10.1.5 Show margin/deficit for each asset
- [ ] 10.1.6 Support interactive exploration
- [ ] 10.1.7 Export MOSCA analysis

---

## 11. PQC/Hybrid Recommendation Engine

### 11.1 Migration Recommendations

**User Story**: As a cryptographic engineer, I want NIST-aligned PQC recommendations for each quantum-vulnerable finding so that I know how to migrate to post-quantum cryptography.

**Acceptance Criteria**:
- [ ] 11.1.1 Recommend ML-KEM (FIPS 203) for key establishment
- [ ] 11.1.2 Recommend ML-DSA (FIPS 204) for digital signatures
- [ ] 11.1.3 Recommend SLH-DSA (FIPS 205) where appropriate
- [ ] 11.1.4 Support hybrid cryptography recommendations
- [ ] 11.1.5 Map source algorithm to target algorithm
- [ ] 11.1.6 Consider application context (performance, latency, compatibility)
- [ ] 11.1.7 Provide migration strategy notes
- [ ] 11.1.8 Link to relevant NIST standards

**Examples**:
- ECDH → ML-KEM or ECDH + ML-KEM hybrid
- ECDSA → ML-DSA or appropriate hybrid signature
- RSA encryption → ML-KEM
- RSA signatures → ML-DSA

### 11.2 Migration Strategy Guidance

**Acceptance Criteria**:
- [ ] 11.2.1 Recommend direct PQC migration where feasible
- [ ] 11.2.2 Recommend hybrid mode for compatibility
- [ ] 11.2.3 Recommend crypto-agile abstraction
- [ ] 11.2.4 Recommend protocol-level migration
- [ ] 11.2.5 Estimate migration complexity (low, medium, high)
- [ ] 11.2.6 Identify dependencies and blockers

---

## 12. Migration Roadmap

### 12.1 Prioritized Action Plan

**User Story**: As a product manager, I want a prioritized migration roadmap so that I can schedule PQC migration work across multiple releases.

**Acceptance Criteria**:
- [ ] 12.1.1 Generate phased migration roadmap
- [ ] 12.1.2 Phase 1: Immediate/Critical
- [ ] 12.1.3 Phase 2: High Priority
- [ ] 12.1.4 Phase 3: Planned
- [ ] 12.1.5 Phase 4: Monitor/No Immediate Action
- [ ] 12.1.6 Explain prioritization rationale
- [ ] 12.1.7 List recommended replacement for each item
- [ ] 12.1.8 Identify dependencies and blockers
- [ ] 12.1.9 Estimate migration complexity
- [ ] 12.1.10 Note business impact
- [ ] 12.1.11 Flag validation requirements

---

## 13. Actionable Remediation

### 13.1 Remediation Guidance

**User Story**: As a developer, I want actionable remediation guidance for source code findings so that I know how to fix cryptographic issues.

**Acceptance Criteria**:
- [ ] 13.1.1 Identify current cryptographic pattern
- [ ] 13.1.2 Explain risk
- [ ] 13.1.3 Recommend replacement pattern
- [ ] 13.1.4 Provide migration strategy
- [ ] 13.1.5 Suggest crypto-agile abstractions where appropriate
- [ ] 13.1.6 Link to PQC/hybrid implementation guides

---

## 14. Evidence and Explainability

### 14.1 Finding Evidence

**User Story**: As a security auditor, I want to see the evidence supporting each cryptographic finding so that I can validate discovery accuracy and understand the risk assessment.

**Acceptance Criteria**:
- [ ] 14.1.1 Show what was detected (algorithm, operation)
- [ ] 14.1.2 Show where it was detected (file, line, symbol)
- [ ] 14.1.3 Show code excerpt or evidence snippet
- [ ] 14.1.4 Explain why classified as cryptographic
- [ ] 14.1.5 Explain context classification (production/test/etc.)
- [ ] 14.1.6 Explain quantum vulnerability
- [ ] 14.1.7 Explain risk score calculation
- [ ] 14.1.8 Show MOSCA calculation
- [ ] 14.1.9 Show business risk factors
- [ ] 14.1.10 Show recommended migration
- [ ] 14.1.11 Show confidence level
- [ ] 14.1.12 Avoid black-box scoring

---

## 15. Scan Summary

### 15.1 Executive Summary Report

**User Story**: As a CISO, I want an executive summary after each scan so that I can communicate cryptographic posture to leadership and the board.

**Acceptance Criteria**:
- [ ] 15.1.1 Summarize overall cryptographic posture
- [ ] 15.1.2 Report total assets discovered
- [ ] 15.1.3 Report critical/high-risk asset count
- [ ] 15.1.4 Report quantum-vulnerable asset count
- [ ] 15.1.5 Report HNDL exposure
- [ ] 15.1.6 Highlight most important algorithms
- [ ] 15.1.7 Highlight most critical applications
- [ ] 15.1.8 List top migration priorities
- [ ] 15.1.9 Recommend PQC/hybrid strategy
- [ ] 15.1.10 Assess overall migration readiness
- [ ] 15.1.11 Use language understandable to non-technical executives

---

## 16. Search, Filter, and Drill-Down

### 16.1 Inventory Navigation

**User Story**: As a security analyst, I want to filter and search cryptographic inventory so that I can quickly find specific algorithms, applications, or risk levels.

**Acceptance Criteria**:
- [ ] 16.1.1 Filter by algorithm
- [ ] 16.1.2 Filter by risk level
- [ ] 16.1.3 Filter by business criticality
- [ ] 16.1.4 Filter by target type
- [ ] 16.1.5 Filter by application/service
- [ ] 16.1.6 Filter by environment
- [ ] 16.1.7 Filter by quantum status
- [ ] 16.1.8 Filter by HNDL status
- [ ] 16.1.9 Filter by migration priority
- [ ] 16.1.10 Filter by confidence level
- [ ] 16.1.11 Support text search
- [ ] 16.1.12 Navigate from aggregate number to detail

---

## 17. Scan History

### 17.1 Historical Analysis

**User Story**: As a compliance manager, I want to compare scans over time so that I can track migration progress and report on cryptographic risk reduction.

**Acceptance Criteria**:
- [ ] 17.1.1 Persist scan results with timestamp
- [ ] 17.1.2 Display scan history list
- [ ] 17.1.3 Support scan-to-scan comparison
- [ ] 17.1.4 Show newly discovered crypto assets
- [ ] 17.1.5 Show removed crypto assets
- [ ] 17.1.6 Show risk changes
- [ ] 17.1.7 Show migration progress
- [ ] 17.1.8 Show remaining quantum-vulnerable assets
- [ ] 17.1.9 Track CBOM changes over time
- [ ] 17.1.10 Support tenant-scoped history

---

## 18. Platform Differentiation

### 18.1 Intelligence Platform vs Basic Scanner

**User Story**: As a stakeholder, I want to understand that QRYPTON is a cryptographic intelligence platform, not just a keyword scanner.

**Acceptance Criteria**:
- [ ] 18.1.1 Demonstrate contextual classification, not just detection
- [ ] 18.1.2 Demonstrate CBOM generation
- [ ] 18.1.3 Demonstrate quantum analysis beyond "RSA found"
- [ ] 18.1.4 Demonstrate MOSCA risk modeling
- [ ] 18.1.5 Demonstrate business risk scoring
- [ ] 18.1.6 Demonstrate prioritization
- [ ] 18.1.7 Demonstrate PQC/hybrid recommendations
- [ ] 18.1.8 Demonstrate migration roadmap
- [ ] 18.1.9 Demonstrate actionable remediation
- [ ] 18.1.10 Prove value beyond static PDF reports

**Platform Value Chain**:
```
Cryptographic Discovery
  ↓
Contextual Classification
  ↓
CBOM
  ↓
Quantum Analysis
  ↓
MOSCA Risk
  ↓
Business Risk
  ↓
Prioritization
  ↓
PQC/Hybrid Recommendation
  ↓
Migration Roadmap
  ↓
Actionable Remediation
```

---

## 19. User Experience Requirements

### 19.1 Post-Scan Dashboard

**User Story**: As any user, after a successful scan, I want a comprehensive dashboard so that I can understand results and take action.

**Acceptance Criteria**:
- [ ] 19.1.1 Display executive summary
- [ ] 19.1.2 Display cryptographic inventory table
- [ ] 19.1.3 Display CBOM export option
- [ ] 19.1.4 Display risk dashboard with KPIs
- [ ] 19.1.5 Display quantum risk analysis
- [ ] 19.1.6 Display MOSCA urgency matrix
- [ ] 19.1.7 Display critical findings list
- [ ] 19.1.8 Display evidence/source locations
- [ ] 19.1.9 Display PQC/hybrid recommendations
- [ ] 19.1.10 Display migration roadmap
- [ ] 19.1.11 Display remediation recommendations
- [ ] 19.1.12 Display scan history and comparison tools

### 19.2 Professional Experience

**Acceptance Criteria**:
- [ ] 19.2.1 Feel like enterprise intelligence platform
- [ ] 19.2.2 Not feel like basic source scanner
- [ ] 19.2.3 Support both technical and executive audiences
- [ ] 19.2.4 Provide clear visual hierarchy
- [ ] 19.2.5 Use professional data visualization
- [ ] 19.2.6 Support export and sharing

---

## 20. Demonstration Quality

### 20.1 Benchmark Test Case

**User Story**: As a product evaluator, I want to see QRYPTON analyze a real-world cryptographic codebase so that I can validate its intelligence and accuracy.

**Benchmark Repository**: https://github.com/pyca/cryptography

**Acceptance Criteria**:
- [ ] 20.1.1 Scan pyca/cryptography repository
- [ ] 20.1.2 Distinguish library capabilities from usage
- [ ] 20.1.3 Identify test vectors vs production crypto
- [ ] 20.1.4 Identify test material accurately
- [ ] 20.1.5 Recognize documentation/examples
- [ ] 20.1.6 Identify quantum-vulnerable algorithms
- [ ] 20.1.7 Identify migration-relevant assets
- [ ] 20.1.8 Generate accurate counts from evidence
- [ ] 20.1.9 Do not hard-code expected results
- [ ] 20.1.10 Prove understanding beyond keyword matching

### 20.2 Ultimate Objective

**Prove**: "QRYPTON does not merely find cryptography. It understands where cryptography exists, how it is being used, how much quantum/business risk it creates, which assets matter most, and what the organization should do next."

---

## Non-Functional Requirements

### Performance
- [ ] NFR-1: Scan completion within reasonable time (< 10 min for typical repo)
- [ ] NFR-2: Support large codebases (> 100k LOC)
- [ ] NFR-3: Handle concurrent scans

### Security
- [ ] NFR-4: Never store or log private keys or secrets
- [ ] NFR-5: Redact sensitive information in reports
- [ ] NFR-6: Support secure credential management for integrations

### Scalability
- [ ] NFR-7: Support multi-tenant operation
- [ ] NFR-8: Support scan result persistence
- [ ] NFR-9: Support result pagination and filtering

### Usability
- [ ] NFR-10: Intuitive UI for non-cryptography experts
- [ ] NFR-11: Comprehensive tooltips and help text
- [ ] NFR-12: Accessible interface (WCAG compliance)

---

## Success Criteria

The Cryptographic Discovery Workflow is successful when:

1. **Discovery**: All 6 target types supported with accurate crypto detection
2. **Context**: Findings classified with usage context (not just "RSA found")
3. **CBOM**: Standardized, exportable cryptographic inventory
4. **Quantum Risk**: Accurate quantum vulnerability and HNDL assessment
5. **MOSCA**: Timeline-based urgency modeling (X + Y > Z)
6. **Business Risk**: Contextualized risk scoring
7. **Prioritization**: Clear separation of critical from informational findings
8. **Recommendations**: Actionable PQC/hybrid migration guidance
9. **Roadmap**: Phased, prioritized migration plan
10. **Evidence**: Transparent, explainable results with code references
11. **Experience**: Professional platform feel, not basic scanner
12. **Benchmark**: Successfully analyzes pyca/cryptography with intelligence

---

## Out of Scope (for initial release)

- Automated code refactoring/patching
- Runtime cryptographic monitoring
- Key management service integration beyond metadata
- Real-time threat intelligence correlation
- Automated penetration testing
- Blockchain/cryptocurrency analysis
- Physical device inspection (HSMs, smart cards)
