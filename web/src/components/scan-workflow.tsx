"use client";

import { useEffect, useState } from "react";
import { AlertCircle, ArrowLeft, ArrowRight, CheckCircle2, Info, Loader2, Package, X } from "lucide-react";
import { Alert, Badge, Button, Card, CardContent, CardHeader, CardTitle, Input } from "@/components/ui/primitives";

export type ScanInputMode = "url" | "upload" | "local" | "arn" | "reference";

export type ScanForm = {
  target_type: string;
  /** Canonical locator: repo URL, container image reference (nginx:latest), KMS identifier (AWS ARN / Azure / GCP), server-local path, or upload://<id>. */
  repository: string;
  artifact_id: string | null;
  artifact_name: string;
  /** Preserved original-upload metadata: shown in the UI and sent downstream. */
  artifact_format: string;
  artifact_size_bytes: number | null;
  artifact_content_type: string;
  input_mode: ScanInputMode;
  branch: string; system_name: string; owner: string;
  environment: string; business_criticality: string; data_sensitivity: string; data_lifetime: number;
  internet_exposure: boolean; regulatory_relevance: string; migration_complexity: string;
  migration_time: number; crqc_horizon: number;
};

export const DEFAULT_SCAN_FORM: ScanForm = {
  target_type: "source_repo",
  repository: "",
  artifact_id: null,
  artifact_name: "",
  artifact_format: "",
  artifact_size_bytes: null,
  artifact_content_type: "",
  input_mode: "url",
  branch: "",
  system_name: "",
  owner: "",
  environment: "production",
  business_criticality: "critical",
  data_sensitivity: "restricted",
  data_lifetime: 7.0,
  internet_exposure: true,
  regulatory_relevance: "regulated",
  migration_complexity: "high",
  migration_time: 4.0,
  crqc_horizon: 8.0,
};

export const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";
const MAX_UPLOAD_BYTES = 64 * 1024 * 1024;
type Props = {
  open: boolean;
  onClose: () => void;
  form: ScanForm;
  setForm: (form: ScanForm) => void;
  onSubmit: () => Promise<void>;
  submitting: boolean;
  successMessage: string | null;
  submitError?: string | null;
  polling?: boolean;
  phaseMessage?: string | null;
  elapsedMs?: number;
};

// Dynamic polling timeouts by target type (mirrors page.tsx).
export const SCAN_TIMEOUT_DEFAULT_MS = 15000; // Archives, Binaries, Manifests, KMS
export const SCAN_TIMEOUT_MEDIUM_MS = 60000; // Source Repositories
export const SCAN_TIMEOUT_EXTENDED_MS = 120000; // Container Images, Heavy Repos
const HEAVY_REPO_HINT = /(monorepo|heavy|large|enterprise|chromium|linux|kernel|opencv|tensorflow)/i;

export function getScanTimeoutForTarget(targetType: string, repository?: string): number {
  const normalized = String(targetType ?? "").trim().toLowerCase();
  if (normalized === "container_image") return SCAN_TIMEOUT_EXTENDED_MS;
  if (normalized === "source_repo") {
    const repo = String(repository ?? "");
    const isHeavy =
      HEAVY_REPO_HINT.test(repo) || repo.length > 80 || (repo.match(/\//g) ?? []).length > 4;
    return isHeavy ? SCAN_TIMEOUT_EXTENDED_MS : SCAN_TIMEOUT_MEDIUM_MS;
  }
  return SCAN_TIMEOUT_DEFAULT_MS;
}

export function getScanPhaseMessage(elapsedMs: number): string {
  if (elapsedMs < 5000) return "Connecting to target & initializing engine...";
  if (elapsedMs < 15000) return "Fetching remote assets & parsing static patterns...";
  return "Deep AST analysis & generating CycloneDX 1.6 CBOM...";
}
const steps = ["Target type", "Provide target", "Business context", "Review & start"];
const stages = ["Acquiring target", "Validating target", "Discovering evidence", "Normalizing cryptographic observations", "Correlating duplicate evidence", "Assessing risk", "Generating recommendations", "Preparing CBOM / report"];
const targetTypes = [
  ["source_repo", "Source Code", "Repository URL, uploaded ZIP, or local checkout. Analyzed statically, never executed."],
  ["source_archive", "Source Archive", "Inspect an uploaded source artifact only."],
  ["binary", "Binary", "Upload a binary or point at a local artifact (ELF, PE, Mach-O). Never run."],
  ["dependency_manifest", "Library / Package", "Upload a package or point at a local artifact; crypto dependencies mapped into the CBOM."],
  ["container_image", "Container", "Image reference or uploaded image archive. Layers read without starting a container."],
  ["cloud_kms", "Cloud KMS", "KMS resource identifier or ARN. Key metadata only — key material never requested."],
] as const;

type TargetInputSpec = {
  modes: ScanInputMode[];
  defaultMode: ScanInputMode;
  title: string;
  subtitle: string;
  urlPlaceholder: string;
  urlHint: string;
  localLabel: string;
  localPlaceholder: string;
  localHint: string;
  accept: string;
  uploadTabLabel: string;
  uploadCta: string;
  uploadHint: string;
  arnPlaceholder: string;
  arnHint: string;
  referencePlaceholder: string;
  referenceHint: string;
  showBranch: boolean;
};

const TARGET_INPUTS: Record<string, TargetInputSpec> = {
  source_repo: {
    modes: ["url", "upload", "local"],
    defaultMode: "url",
    title: "Provide source repository or upload source artifact",
    subtitle: "Repository URL, uploaded ZIP, or local checkout. Analyzed statically, never executed.",
    urlPlaceholder: "https://github.com/org/repo, https://gitlab.com/group/repo, or https://bitbucket.org/owner/repo",
    urlHint: "GitHub, GitLab, or Bitbucket HTTPS URL. The backend fetches a bounded archive snapshot — it never clones with credentials or executes code.",
    localLabel: "Server-local source path",
    localPlaceholder: "C:\\repos\\payments-core or /srv/repos/payments-core",
    localHint: "Server-local source directory. Must exist on the machine running the scan service.",
    accept: ".zip,.tar,.tar.gz,.tgz,.tar.bz2,.tar.xz",
    uploadTabLabel: "Upload archive",
    uploadCta: "Choose source archive to upload",
    uploadHint: "Upload a source-code ZIP or tarball (max 64 MiB). It is inspected statically and never executed.",
    arnPlaceholder: "",
    arnHint: "",
    referencePlaceholder: "",
    referenceHint: "",
    showBranch: true,
  },
  source_archive: {
    modes: ["upload", "local"],
    defaultMode: "upload",
    title: "Upload source archive artifact",
    subtitle: "Uploaded archives are extracted in a bounded sandbox and never executed.",
    urlPlaceholder: "",
    urlHint: "",
    localLabel: "Server-local archive path",
    localPlaceholder: "C:\\artifacts\\build.tar.gz or /srv/artifacts/source-code.zip",
    localHint: "Server-local archive file. Bounded extraction, symlinks and traversal paths rejected.",
    accept: ".zip,.tar,.tar.gz,.tgz,.tar.bz2,.tar.xz",
    uploadTabLabel: "Upload archive",
    uploadCta: "Choose source archive to upload",
    uploadHint: "Upload the source archive to scan (max 64 MiB).",
    arnPlaceholder: "",
    arnHint: "",
    referencePlaceholder: "",
    referenceHint: "",
    showBranch: false,
  },
  binary: {
    modes: ["upload", "local"],
    defaultMode: "upload",
    title: "Upload binary artifact",
    subtitle: "Binaries are inspected statically — imports, symbols, libraries, certificates. Never run.",
    urlPlaceholder: "",
    urlHint: "",
    localLabel: "Server-local binary path",
    localPlaceholder: "C:\\bin\\crypto_module.dll or /usr/bin/app-service",
    localHint: "Server-local executable file. Supported: ELF, PE, Mach-O.",
    accept: ".exe,.dll,.so,.dylib,.a,.lib,.o,.bin,.elf,.out,.sys,.drv,.apk,.ipa",
    uploadTabLabel: "Upload binary",
    uploadCta: "Choose binary artifact to upload",
    uploadHint: "Upload the binary to inspect (max 64 MiB). Static inspection only — imports, symbols, libraries, certificates. Never executed.",
    arnPlaceholder: "",
    arnHint: "",
    referencePlaceholder: "",
    referenceHint: "",
    showBranch: false,
  },
  dependency_manifest: {
    modes: ["upload", "local"],
    defaultMode: "upload",
    title: "Upload library or package artifact",
    subtitle: "Declared libraries and crypto dependencies are mapped into the CBOM.",
    urlPlaceholder: "",
    urlHint: "",
    localLabel: "Server-local package path",
    localPlaceholder: "C:\\packages\\app.jar or /srv/packages/requirements.txt",
    localHint: "Server-local package, library, or manifest file.",
    accept: ".jar,.war,.aar,.dll,.so,.dylib,.a,.lib,.whl,.tar.gz,.tgz,.zip,.json,.txt,.lock,.toml,.xml,.gradle,.cfg,.ini,.yaml,.yml",
    uploadTabLabel: "Upload package",
    uploadCta: "Choose library or package to upload",
    uploadHint: "Upload the library, package archive, or dependency manifest (package.json, requirements.txt, Cargo.lock, JAR, wheel…) — max 64 MiB.",
    arnPlaceholder: "",
    arnHint: "",
    referencePlaceholder: "",
    referenceHint: "",
    showBranch: false,
  },
  container_image: {
    modes: ["reference", "upload", "local"],
    defaultMode: "reference",
    title: "Provide container image or upload image archive",
    subtitle: "Image layers and metadata are read statically, without starting a container.",
    urlPlaceholder: "",
    urlHint: "",
    localLabel: "Server-local image archive path",
    localPlaceholder: "C:\\images\\app.tar or /srv/images/app.tar",
    localHint: "Server-local OCI/Docker archive (docker save output). Layers, files, packages, libraries, and configuration are read without starting a container.",
    accept: ".tar,.tar.gz,.tgz",
    uploadTabLabel: "Upload archive",
    uploadCta: "Choose image archive to upload",
    uploadHint: "Upload an OCI/Docker image archive (docker save -o image.tar <image>, max 64 MiB). Layers are read statically without starting a container.",
    arnPlaceholder: "",
    arnHint: "",
    referencePlaceholder: "nginx:latest or company/service:1.4.2",
    referenceHint: "Docker Hub style image reference (e.g. nginx:latest, company/service:1.4.2). Recorded as the CBOM container asset — the registry is never pulled and the container is never started. For layer inspection, upload the docker save archive instead.",
    showBranch: false,
  },
  cloud_kms: {
    modes: ["arn", "upload"],
    defaultMode: "arn",
    title: "Provide cloud KMS key/resource identifier",
    subtitle: "Key metadata only — key material is never requested or accessed.",
    urlPlaceholder: "",
    urlHint: "",
    localLabel: "",
    localPlaceholder: "",
    localHint: "",
    accept: ".json",
    uploadTabLabel: "Upload export",
    uploadCta: "Choose key export to upload",
    uploadHint: "Upload a KMS key JSON export (describe-key output, max 64 MiB). Key material is never requested — metadata only.",
    arnPlaceholder: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
    arnHint: "AWS KMS key ARN/ID, Azure Key Vault key identifier (https://<vault>.vault.azure.net/keys/<name>), or GCP KMS resource (projects/.../keyRings/.../cryptoKeys/...). Only the identifier is recorded — key material is never requested or accessed.",
    referencePlaceholder: "",
    referenceHint: "",
    showBranch: false,
  },
};

const FALLBACK_INPUTS: TargetInputSpec = {
  modes: ["local"],
  defaultMode: "local",
  title: "Provide target",
  subtitle: "Provide the actual artifact for this target type. Analysis is static and inspection-only.",
  urlPlaceholder: "",
  urlHint: "",
  localLabel: "Server-local path",
  localPlaceholder: "Server-local path to the artifact",
  localHint: "",
  accept: "",
  uploadTabLabel: "Upload file",
  uploadCta: "Choose file to upload",
  uploadHint: "",
  arnPlaceholder: "",
  arnHint: "",
  referencePlaceholder: "",
  referenceHint: "",
  showBranch: false,
};

export function specForTarget(targetType: string): TargetInputSpec {
  return TARGET_INPUTS[targetType] ?? FALLBACK_INPUTS;
}

const MODE_LABELS: Record<ScanInputMode, string> = {
  url: "Repository URL",
  upload: "Upload file",
  local: "Local path",
  arn: "KMS key identifier",
  reference: "Image reference",
};

/** Friendly target-type names for the Review & Start screen. */
export const TARGET_DISPLAY_NAMES: Record<string, string> = {
  source_repo: "Source Code",
  source_archive: "Source Archive",
  binary: "Binary",
  dependency_manifest: "Library",
  container_image: "Container",
  cloud_kms: "Cloud KMS",
};

export function kmsProviderDisplayName(provider: string): string {
  const normalized = (provider || "").trim().toLowerCase();
  if (normalized === "azure") return "Azure Key Vault";
  if (normalized === "gcp") return "Google Cloud KMS";
  return "AWS KMS";
}

export function gitRepoDisplayPath(url: string): string {
  // https://github.com/company/project(.git) → company/project
  const trimmed = (url || "").trim().replace(/\.git$/i, "").replace(/\/+$/, "");
  const match = trimmed.match(/^https?:\/\/[^/]+\/(.+)$/i);
  return (match?.[1] ?? trimmed).trim() || trimmed;
}

function uploadedArtifactSummary(
  form: Pick<ScanForm, "artifact_name" | "artifact_format" | "artifact_size_bytes">
): string {
  const format = form.artifact_format || artifactFormatFromName(form.artifact_name);
  const size =
    form.artifact_size_bytes !== null && form.artifact_size_bytes !== undefined
      ? `, ${formatBytes(form.artifact_size_bytes)}`
      : "";
  return `${form.artifact_name} (${format}${size})`;
}

/** Target-aware Review & Start rows showing the ACTUAL selected target.
 *
 * The review never labels a non-repository target "Repository URL": repository
 * wording (provider-specific, e.g. "GitHub repository") appears only for the
 * source_repo URL flow; every other target names its own artifact, image
 * reference, or key identifier.
 */
export function buildReviewRows(form: ScanForm): Array<[string, string]> {
  const friendly = TARGET_DISPLAY_NAMES[form.target_type] ?? form.target_type;
  const rows: Array<[string, string]> = [["Target type", friendly]];
  const orDash = (value: string) => (value.trim() ? value : "—");
  switch (form.target_type) {
    case "source_repo":
      if (form.input_mode === "upload" && form.artifact_id) {
        rows.push(["Target", `Uploaded archive: ${uploadedArtifactSummary(form)}`]);
      } else if (form.input_mode === "local") {
        rows.push(["Target", `Local checkout: ${orDash(form.repository)}`]);
      } else {
        const provider = gitProviderFor(form.repository);
        const providerName =
          provider === "gitlab" ? "GitLab" : provider === "bitbucket" ? "Bitbucket" : "GitHub";
        rows.push(["Target", `${providerName} repository: ${gitRepoDisplayPath(form.repository)}`]);
        rows.push(["Branch", form.branch || "main"]);
      }
      break;
    case "source_archive":
      rows.push([
        "Target",
        form.artifact_id
          ? `Uploaded archive: ${uploadedArtifactSummary(form)}`
          : `Local archive: ${orDash(form.repository)}`,
      ]);
      break;
    case "binary":
      rows.push([
        "Target",
        form.artifact_id
          ? `Uploaded binary: ${uploadedArtifactSummary(form)}`
          : `Local binary: ${orDash(form.repository)}`,
      ]);
      break;
    case "dependency_manifest":
      rows.push([
        "Target",
        form.artifact_id
          ? `Uploaded package: ${uploadedArtifactSummary(form)}`
          : `Local package: ${orDash(form.repository)}`,
      ]);
      break;
    case "container_image":
      if (form.input_mode === "reference") {
        rows.push(["Target", orDash(form.repository)]);
      } else if (form.artifact_id) {
        rows.push(["Target", `Uploaded image archive: ${uploadedArtifactSummary(form)}`]);
      } else {
        rows.push(["Target", `Local image archive: ${orDash(form.repository)}`]);
      }
      break;
    case "cloud_kms":
      if (form.input_mode === "arn") {
        rows.push(["Target", kmsProviderDisplayName(kmsProviderFor(form.repository))]);
        rows.push(["Key identifier", orDash(form.repository)]);
      } else {
        rows.push(["Target", `Uploaded key export: ${uploadedArtifactSummary(form)}`]);
      }
      break;
    default:
      rows.push(["Target", orDash(describeScanTarget(form))]);
      break;
  }
  rows.push(
    ["System", `${form.system_name} · ${form.owner}`],
    ["Risk context", `${form.environment} · ${form.business_criticality} · ${form.data_sensitivity}`],
    [
      "Resource limits",
      `Static inspection only · no execution · ${(getScanTimeoutForTarget(form.target_type, form.repository) / 1000).toFixed(0)}s timeout`,
    ],
    ["Mosca", `X ${form.data_lifetime} + Y ${form.migration_time} vs Z ${form.crqc_horizon}`]
  );
  return rows;
}

/** Human-readable locator for history, results headers, and review screens. */
export function describeScanTarget(form: Pick<ScanForm, "target_type" | "repository" | "artifact_name" | "artifact_format" | "artifact_size_bytes" | "branch" | "input_mode">): string {
  if (form.artifact_name) {
    const format = form.artifact_format || artifactFormatFromName(form.artifact_name);
    const size = form.artifact_size_bytes !== null && form.artifact_size_bytes !== undefined
      ? ` (${format}, ${formatBytes(form.artifact_size_bytes)})`
      : format ? ` (${format})` : "";
    return `${form.artifact_name}${size}`;
  }
  if (form.target_type === "source_repo" && form.branch && form.input_mode !== "upload") {
    return `${form.repository} (${form.branch})`;
  }
  return form.repository;
}

const HOSTED_GIT = /^https:\/\/(github\.com|gitlab\.com|bitbucket\.org)\/[^/\s]+\/[^/\s]+/i;
const KMS_IDENTIFIER = /^(arn:[^:]+:kms:[^:]*:[^:]*:(key|alias)\/.+|(?:[0-9a-fA-F-]{8,}|alias\/[A-Za-z0-9/_-]+)|https:\/\/[A-Za-z0-9-]+\.vault\.azure\.net\/keys\/[A-Za-z0-9-]+(?:\/[A-Za-z0-9]+)?\/?|projects\/[^/\s]+\/locations\/[^/\s]+\/keyRings\/[^/\s]+\/cryptoKeys\/[^/\s]+(?:\/cryptoKeyVersions\/[^/\s]+)?)$/i;
const CONTAINER_REFERENCE = /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?)*$/;

export function isValidContainerReference(value: string): boolean {
  const raw = value.trim();
  if (!raw || raw.length > 255 || raw.includes("://") || raw.includes(" ")) return false;
  if (!CONTAINER_REFERENCE.test(raw)) return false;
  const first = raw.split("/", 1)[0] ?? "";
  if (raw.includes("/")) return !first.includes(".") && !first.includes(":");
  const base = first.split(/[:@]/, 1)[0] ?? "";
  return !base.includes(".");
}

export function isValidKmsIdentifier(value: string): boolean {
  return KMS_IDENTIFIER.test(value.trim());
}

export function formatBytes(size: number | null | undefined): string {
  if (size === null || size === undefined || Number.isNaN(size)) return "unknown size";
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KiB`;
  return `${(size / (1024 * 1024)).toFixed(2)} MiB`;
}

export function artifactFormatFromName(name: string): string {
  const lower = (name || "").toLowerCase();
  for (const compound of [".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".tbz2"]) {
    if (lower.endsWith(compound)) return compound.replace(/^\./, "");
  }
  const parts = lower.split(".");
  return parts.length > 1 ? (parts[parts.length - 1] ?? "unknown") : "unknown";
}

export function kmsProviderFor(identifier: string): "aws" | "azure" | "gcp" {
  const raw = (identifier || "").trim();
  if (/^https:\/\/[A-Za-z0-9-]+\.vault\.azure\.net\/keys\//i.test(raw)) return "azure";
  if (/^projects\/[^/\s]+\/locations\//i.test(raw)) return "gcp";
  return "aws";
}

export function gitProviderFor(url: string): "github" | "gitlab" | "bitbucket" {
  const lower = (url || "").toLowerCase();
  if (lower.includes("gitlab")) return "gitlab";
  if (lower.includes("bitbucket")) return "bitbucket";
  return "github";
}

export type TargetSourcePayload = Record<string, string | null>;
export type ArtifactMetadataPayload = Record<string, string | number | null>;

/** Structured original-artifact descriptor: binary/manifest/archive uploads,
 * KMS identifiers, container references, and git repos are never flattened
 * into a fake repository representation. */
export function buildTargetSource(form: Pick<ScanForm, "target_type" | "repository" | "artifact_id" | "artifact_name" | "artifact_format" | "branch" | "input_mode">): TargetSourcePayload {
  const targetType = form.target_type;
  if (form.input_mode === "upload" && form.artifact_id) {
    const location = form.repository || `upload://${form.artifact_id}`;
    return {
      type: "uploaded_artifact",
      name: form.artifact_name || null,
      format: form.artifact_format || artifactFormatFromName(form.artifact_name) || null,
      location,
    };
  }
  if (targetType === "cloud_kms" && form.input_mode === "arn") {
    const identifier = form.repository.trim();
    return { type: "kms_identifier", provider: kmsProviderFor(identifier), identifier };
  }
  if (targetType === "container_image" && form.input_mode === "reference") {
    return { type: "container_reference", reference: form.repository.trim() };
  }
  if (targetType === "source_repo" && form.input_mode === "url") {
    return {
      type: "git_repository",
      provider: gitProviderFor(form.repository),
      url: form.repository.trim(),
      branch: form.branch || "main",
    };
  }
  const formatByType: Record<string, string> = {
    binary: "binary",
    source_repo: "source_tree",
    source_archive: "archive",
    dependency_manifest: "manifest",
    container_image: "docker_archive",
  };
  return {
    type: "local_file",
    format: formatByType[targetType] ?? "file",
    location: form.repository.trim(),
  };
}

/** Human-readable summary of what will actually be passed to the scanner. */
export function describeTargetSource(form: Pick<ScanForm, "target_type" | "repository" | "artifact_id" | "artifact_name" | "artifact_format" | "artifact_size_bytes" | "branch" | "input_mode">): string {
  const source = buildTargetSource(form);
  switch (source.type) {
    case "uploaded_artifact":
      return `Uploaded ${String(source.format ?? "artifact")}${source.name ? ` (${source.name})` : ""}`;
    case "kms_identifier": {
      const provider = String(source.provider ?? "kms").toUpperCase();
      return `${provider} KMS key identifier`;
    }
    case "container_reference":
      return `Container reference (${String(source.reference ?? "").trim()})`;
    case "git_repository": {
      const provider = String(source.provider ?? "git");
      const label = provider.charAt(0).toUpperCase() + provider.slice(1);
      return `${label} repository (${String(source.branch || "main")})`;
    }
    case "local_file":
      return `Local ${String(source.format ?? "file")} (${String(source.location ?? "").trim()})`;
    default:
      return describeScanTarget(form);
  }
}

export function buildArtifactMetadata(form: Pick<ScanForm, "artifact_name" | "artifact_format" | "artifact_size_bytes" | "artifact_content_type" | "repository" | "target_type">): ArtifactMetadataPayload {
  const meta: ArtifactMetadataPayload = {};
  if (form.artifact_name) meta.name = form.artifact_name;
  const format = form.artifact_format || (form.artifact_name ? artifactFormatFromName(form.artifact_name) : null);
  if (format) meta.format = format;
  if (form.artifact_size_bytes !== null && form.artifact_size_bytes !== undefined) {
    meta.size_bytes = form.artifact_size_bytes;
  }
  if (form.artifact_content_type) meta.content_type = form.artifact_content_type;
  if (form.repository) meta.location = form.repository;
  return meta;
}

export function ScanWorkflow({ open, onClose, form, setForm, onSubmit, submitting, successMessage, submitError, polling, phaseMessage, elapsedMs }: Props) {
  const [step, setStep] = useState(1);
  const [error, setError] = useState<string | null>(null);
  const [stage, setStage] = useState<number | null>(null);
  const [localElapsedMs, setLocalElapsedMs] = useState(0);
  const activeTimeoutMs = getScanTimeoutForTarget(form.target_type, form.repository);
  // Tick a local elapsed clock while the scan is running so the live status
  // message stays fresh even between polling callbacks.
  useEffect(() => {
    if (stage === null || stage === stages.length) return;
    const startedAt = Date.now() - (elapsedMs ?? 0);
    const timer = window.setInterval(() => {
      const next = Date.now() - startedAt;
      setLocalElapsedMs(next);
    }, 500);
    return () => window.clearInterval(timer);
  }, [stage, elapsedMs]);
  const effectiveElapsedMs = elapsedMs ?? localElapsedMs;
  const livePhaseMessage = phaseMessage ?? getScanPhaseMessage(effectiveElapsedMs);
  const update = (patch: Partial<ScanForm>) => setForm({ ...form, ...patch });
  const [uploading, setUploading] = useState(false);
  const spec = specForTarget(form.target_type);
  const incomplete = !form.system_name || !form.owner || !form.data_sensitivity || !form.regulatory_relevance || !form.migration_complexity;
  const exposed = form.data_lifetime + form.migration_time > form.crqc_horizon;
  /** Switching target types resets the artifact inputs so a repo link can never leak into KMS/binary flows. */
  const selectTargetType = (targetType: string) => {
    const nextSpec = specForTarget(targetType);
    setForm({
      ...form,
      target_type: targetType,
      input_mode: nextSpec.defaultMode,
      repository: "",
      artifact_id: null,
      artifact_name: "",
      artifact_format: "",
      artifact_size_bytes: null,
      artifact_content_type: "",
      branch: "",
    });
    setError(null);
  };
  const selectInputMode = (mode: ScanInputMode) => {
    setForm({ ...form, input_mode: mode, repository: "", artifact_id: null, artifact_name: "", artifact_format: "", artifact_size_bytes: null, artifact_content_type: "" });
    setError(null);
  };
  const onFileSelected = async (file: File | undefined) => {
    if (!file) return;
    if (file.size > MAX_UPLOAD_BYTES) {
      setError(`"${file.name}" exceeds the 64 MiB upload limit. Provide a server-local path instead.`);
      return;
    }
    if (file.size === 0) {
      setError(`"${file.name}" is empty. Select a non-empty artifact.`);
      return;
    }
    setUploading(true);
    setError(null);
    try {
      const body = new FormData();
      body.append("file", file);
      const res = await fetch(`${API_BASE}/api/v1/uploads`, {
        method: "POST",
        body,
        signal: AbortSignal.timeout(activeTimeoutMs),
      });
      if (!res.ok) {
        let detail = `Upload failed (HTTP ${res.status}).`;
        try {
          const data = (await res.json()) as { detail?: unknown };
          if (typeof data.detail === "string" && data.detail) detail = data.detail;
        } catch {
          // Keep the default message.
        }
        throw new Error(detail);
      }
      const data = (await res.json()) as { artifact_id: string; filename: string; locator: string; format?: string; size_bytes?: number; content_type?: string };
      setForm({
        ...form,
        input_mode: "upload",
        artifact_id: data.artifact_id,
        artifact_name: data.filename,
        artifact_format: data.format || artifactFormatFromName(data.filename),
        artifact_size_bytes: typeof data.size_bytes === "number" ? data.size_bytes : file.size,
        artifact_content_type: data.content_type || file.type || "",
        repository: data.locator,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Upload failed. Try again or use a server-local path.");
    } finally {
      setUploading(false);
    }
  };
  const onClearUpload = () => {
    setForm({ ...form, artifact_id: null, artifact_name: "", artifact_format: "", artifact_size_bytes: null, artifact_content_type: "", repository: "" });
    setError(null);
  };
  const validateTargetStep = (): string | null => {
    switch (form.target_type) {
      case "source_repo":
        if (form.input_mode === "url") {
          if (!form.repository.trim()) return "Enter a GitHub, GitLab, or Bitbucket repository URL.";
          if (!HOSTED_GIT.test(form.repository.trim())) {
            return "Enter a valid HTTPS repository URL, e.g. https://github.com/org/repo.";
          }
          return null;
        }
        if (form.input_mode === "upload") {
          return form.artifact_id ? null : "Upload a source-code ZIP or tarball to scan.";
        }
        return form.repository.trim() ? null : "Enter the server-local source directory to scan.";
      case "source_archive":
        if (form.input_mode === "upload") {
          return form.artifact_id ? null : "Upload the source archive to scan.";
        }
        return form.repository.trim() ? null : "Enter the server-local archive path to scan.";
      case "binary":
        if (form.input_mode === "upload") {
          return form.artifact_id ? null : "Upload the binary file to inspect (ELF, PE, or Mach-O).";
        }
        return form.repository.trim() ? null : "Enter the server-local binary path to inspect.";
      case "dependency_manifest":
        if (form.input_mode === "upload") {
          return form.artifact_id ? null : "Upload the library, package, or manifest to analyze.";
        }
        return form.repository.trim() ? null : "Enter the server-local package or manifest path to analyze.";
      case "container_image":
        if (form.input_mode === "reference") {
          if (!form.repository.trim()) return "Enter a container image reference, e.g. nginx:latest or company/service:1.4.2.";
          if (!isValidContainerReference(form.repository)) {
            return "Enter a valid image reference (e.g. nginx:latest, company/service:1.4.2) or upload a docker save archive for registries with a hostname.";
          }
          return null;
        }
        if (form.input_mode === "upload") {
          return form.artifact_id ? null : "Upload the container image archive (docker save output).";
        }
        return form.repository.trim() ? null : "Enter the server-local OCI/Docker archive path (e.g. C:\\images\\app.tar).";
      case "cloud_kms":
        if (form.input_mode === "arn") {
          if (!form.repository.trim()) return "Enter the KMS key identifier — AWS ARN/ID, Azure Key Vault key, or GCP KMS resource (no key material is ever requested).";
          if (!isValidKmsIdentifier(form.repository)) {
            return "Enter a valid KMS identifier: AWS ARN (arn:aws:kms:...), Azure Key Vault (https://<vault>.vault.azure.net/keys/<name>), or GCP (projects/.../keyRings/.../cryptoKeys/...).";
          }
          return null;
        }
        return form.artifact_id ? null : "Upload the KMS key JSON export to review.";
      default:
        return form.repository.trim() ? null : "Provide the target artifact.";
    }
  };
  const validate = () => {
    if (step === 1 && !form.target_type) return "Select a target type.";
    if (step === 2) return validateTargetStep();
    if (step === 3 && (!form.system_name.trim() || !form.owner.trim())) return "System name and owner are required.";
    if ([form.data_lifetime, form.migration_time, form.crqc_horizon].some((v) => v < 0)) return "Horizon values cannot be negative.";
    return null;
  };
  const next = () => { const issue = validate(); if (issue) setError(issue); else { setError(null); setStep((v) => v + 1); } };
  useEffect(() => {
    if (!open) {
      // eslint-disable-next-line react-hooks/set-state-in-effect -- reset wizard when modal closes
      setStep(1);
      setError(null);
      setStage(null);
      setLocalElapsedMs(0);
    }
  }, [open]);
  const start = async () => {
    const issue = validate();
    if (issue) return setError(issue);
    setError(null);
    setStage(0);
    // Dynamic timeout budget derived from the selected target type.
    const SCAN_TIMEOUT = getScanTimeoutForTarget(form.target_type, form.repository);
    const POLLING_TIMEOUT = SCAN_TIMEOUT;
    const startTime = Date.now();
    try {
      const submitPromise = onSubmit();
      for (let i = 0; i < stages.length; i += 1) {
        // Check if we've exceeded the polling timeout
        if (Date.now() - startTime > POLLING_TIMEOUT) {
          console.warn(`Polling timeout exceeded after ${POLLING_TIMEOUT}ms, forcing completion`);
          setStage(stages.length);
          break;
        }
        setStage(i);
        await Promise.race([
          submitPromise.then(() => undefined).catch(() => undefined),
          new Promise((resolve) => window.setTimeout(resolve, 350)),
        ]);
      }
      // Add timeout to final await to prevent infinite loading on CBOM preparation
      await Promise.race([
        submitPromise.then(() => undefined).catch(() => undefined),
        new Promise((resolve) => window.setTimeout(resolve, SCAN_TIMEOUT)),
      ]);
      setStage(stages.length);
    } catch (err) {
      // Capture current stage value for the timeout callback
      const currentStage = stage;
      setStage(null);
      setError(err instanceof Error ? err.message : "Scan failed.");
      // Fallback: force completion after error to prevent stuck state
      setTimeout(() => {
        if (currentStage !== null && currentStage !== stages.length) {
          console.warn("Forcing scan completion due to error during polling");
          setStage(stages.length);
        }
      }, 2000);
    }
  };
  const close = () => { setStep(1); setError(null); setStage(null); onClose(); };
  const visibleError = error || submitError;
  if (!open) return null;
  return <div className="fixed inset-0 z-50 flex items-center justify-center p-4" role="dialog" aria-modal="true"><button className="absolute inset-0 bg-foreground/40 backdrop-blur-sm" aria-label="Close" onClick={close} /><Card className="relative flex max-h-[calc(100vh-2rem)] w-full max-w-3xl flex-col overflow-hidden bg-card"><CardHeader className="border-b border-border p-5"><div className="flex justify-between gap-4"><div><p className="qrypton-kicker">Guided workflow</p><CardTitle className="mt-1">New cryptographic scan</CardTitle><p className="mt-1 text-sm text-muted-foreground">Static inspection only—QRYPTON does not execute, deploy, or modify a target.</p></div><Button variant="ghost" onClick={close}><X /></Button></div><div className="mt-5 flex gap-2 overflow-x-auto">{steps.map((label, i) => <div key={`${label}-${i}`} className="flex items-center gap-2"><span className={`flex size-7 items-center justify-center rounded-full text-xs ${i + 1 <= step ? "bg-primary text-primary-foreground" : "border border-border"}`}>{i + 1}</span><span className="text-xs text-muted-foreground">{label}</span></div>)}</div></CardHeader><CardContent className="overflow-y-auto p-5">
    {stage !== null ? <div className="space-y-3"><h3 className="font-semibold">{stage === stages.length ? (successMessage || "Scan completed") : "Scan in progress"}</h3><p className="text-sm text-muted-foreground">{stage === stages.length ? "Opening results." : `Inspecting the target (${form.target_type} · ${(activeTimeoutMs / 1000).toFixed(0)}s budget). Keep this window open until the run finishes.`}</p><div className="flex items-center gap-3 rounded-md border border-primary/40 bg-primary/5 p-3 text-sm" role="status" aria-live="polite">{submitting || polling || stage < stages.length ? <Loader2 className="size-5 animate-spin text-primary" /> : <CheckCircle2 className="size-5 text-emerald-400" />}<span>{submitting || polling || stage < stages.length ? livePhaseMessage : "Results are ready."}</span></div>{stage !== stages.length && <p className="text-xs tabular-nums text-muted-foreground" aria-live="polite">Elapsed {(effectiveElapsedMs / 1000).toFixed(1)}s of {(activeTimeoutMs / 1000).toFixed(0)}s · polling every 1.5s</p>}{stages.map((label, i) => <div key={`${label}-${i}`} className={`flex items-center gap-3 rounded-md border p-3 text-sm ${i < stage ? "border-emerald-500/30 bg-emerald-500/10" : i === stage ? "border-primary bg-primary/5" : "border-border text-muted-foreground"}`}>{i < stage || stage === stages.length ? <CheckCircle2 className="size-4 text-emerald-400" /> : i === stage ? <Loader2 className="size-4 animate-spin text-primary" /> : <span className="size-4" />}{i + 1}. {label}</div>)}</div> : <>
    {step === 1 && <div><h3 className="font-semibold">Select target type</h3><p className="mt-1 text-sm text-muted-foreground">Select what contains the cryptographic evidence.</p><div className="mt-4 grid gap-3 sm:grid-cols-2">{targetTypes.map(([value, label, note]) => <button key={value} type="button" onClick={() => selectTargetType(value)} className={`rounded-lg border p-4 text-left ${form.target_type === value ? "border-primary bg-primary/5 ring-1 ring-primary" : "border-border hover:bg-muted"}`}><span className="block text-sm font-semibold">{label}</span><span className="mt-1 block text-xs leading-5 text-muted-foreground">{note}</span></button>)}</div></div>}
    {step === 2 && <TargetInputs form={form} update={update} spec={spec} uploading={uploading} onSelectMode={selectInputMode} onFileSelected={(file) => void onFileSelected(file)} onClearUpload={onClearUpload} />}
    {step === 3 && <div className="space-y-4"><h3 className="font-semibold">Business context</h3><div className="grid gap-3 sm:grid-cols-2"><Field label="System name" value={form.system_name} onChange={(v) => update({ system_name: v })} placeholder="e.g. payments-core" /><Field label="Owner" value={form.owner} onChange={(v) => update({ owner: v })} placeholder="e.g. team-crypto" /><Select label="Environment" value={form.environment} options={["production", "staging", "development"]} onChange={(v) => update({ environment: v })} /><Select label="Business criticality" value={form.business_criticality} options={["critical", "high", "medium", "low"]} onChange={(v) => update({ business_criticality: v })} /><Select label="Data sensitivity" value={form.data_sensitivity} options={["restricted", "confidential", "internal", "public"]} onChange={(v) => update({ data_sensitivity: v })} /><Select label="Regulatory relevance" value={form.regulatory_relevance} options={["regulated", "contractual", "none"]} onChange={(v) => update({ regulatory_relevance: v })} /><Select label="Migration complexity" value={form.migration_complexity} options={["high", "medium", "low"]} onChange={(v) => update({ migration_complexity: v })} /><label className="flex items-center gap-3 rounded-md border border-border p-3 text-sm"><input type="checkbox" checked={form.internet_exposure} onChange={(e) => update({ internet_exposure: e.target.checked })} />Internet exposed</label></div><div className="rounded-lg border border-border bg-muted/40 p-4"><div className="flex justify-between"><span className="text-sm font-semibold">Mosca urgency: X + Y vs Z</span><Badge tone={exposed ? "critical" : "success"}>{exposed ? "Urgent" : "Within horizon"}</Badge></div><div className="mt-3 grid gap-3 sm:grid-cols-3"><NumberField label="Data lifetime X" value={form.data_lifetime} onChange={(v) => update({ data_lifetime: v })} /><NumberField label="Migration effort Y" value={form.migration_time} onChange={(v) => update({ migration_time: v })} /><NumberField label="CRQC horizon Z" value={form.crqc_horizon} onChange={(v) => update({ crqc_horizon: v })} /></div></div>{incomplete && <Alert className="border-amber-500/30 bg-amber-500/10"><AlertCircle className="text-amber-400" /><span>Business context incomplete — confidence reduced. Missing context does not lower risk.</span></Alert>}</div>}
    {step === 4 && <div className="space-y-4"><h3 className="font-semibold">Review scope and limits</h3><div className="divide-y divide-border rounded-lg border border-border">{buildReviewRows(form).map(([label, value]) => <div key={label} className="flex justify-between gap-4 p-3 text-sm"><span className="text-muted-foreground">{label}</span><span className="text-right font-medium break-all">{value}</span></div>)}</div></div>}</>}{visibleError && <Alert className="mt-4 border-destructive/30 bg-rose-500/10"><AlertCircle className="text-destructive" /><span>{visibleError}</span></Alert>}</CardContent><div className="flex justify-between border-t border-border p-5"><Button variant="ghost" onClick={step === 1 ? close : () => setStep((v) => v - 1)} disabled={stage !== null}><ArrowLeft />{step === 1 ? "Cancel" : "Back"}</Button>{stage === null && (step < 4 ? <Button onClick={next} disabled={uploading}>{uploading ? "Uploading…" : <>Continue <ArrowRight /></>}</Button> : <Button onClick={start} disabled={submitting || uploading}><Package />{uploading ? "Uploading…" : "Start scan"}</Button>)}{stage === stages.length && <Button onClick={close}>Close</Button>}</div></Card></div>;
}
function TargetInputs({
  form,
  update,
  spec,
  uploading,
  onSelectMode,
  onFileSelected,
  onClearUpload,
}: {
  form: ScanForm;
  update: (patch: Partial<ScanForm>) => void;
  spec: TargetInputSpec;
  uploading: boolean;
  onSelectMode: (mode: ScanInputMode) => void;
  onFileSelected: (file: File | undefined) => void;
  onClearUpload: () => void;
}) {
  return (
    <div className="space-y-4">
      <div>
        <h3 className="font-semibold">{spec.title}</h3>
        <p className="mt-1 text-sm text-muted-foreground">{spec.subtitle}</p>
      </div>
      {spec.modes.length > 1 && (
        <div className="flex flex-wrap gap-2" role="tablist" aria-label="Input method">
          {spec.modes.map((mode) => (
            <button
              key={mode}
              type="button"
              role="tab"
              aria-selected={form.input_mode === mode}
              onClick={() => onSelectMode(mode)}
              className={`rounded-full border px-3 py-1.5 text-xs font-semibold transition-colors ${
                form.input_mode === mode
                  ? "border-primary bg-primary/10 text-primary"
                  : "border-border text-muted-foreground hover:bg-muted hover:text-foreground"
              }`}
            >
              {mode === "upload" ? spec.uploadTabLabel || MODE_LABELS[mode] : MODE_LABELS[mode]}
            </button>
          ))}
        </div>
      )}
      {form.input_mode === "url" && (
        <div className="space-y-3">
          <label className="flex flex-col gap-2 text-sm font-medium">
            Repository URL
            <Input
              value={form.repository}
              onChange={(e) => update({ repository: e.target.value })}
              placeholder={spec.urlPlaceholder}
              inputMode="url"
            />
          </label>
          <p className="text-xs leading-5 text-muted-foreground">{spec.urlHint}</p>
          {spec.showBranch && (
            <label className="flex flex-col gap-2 text-sm font-medium">
              Branch or tag
              <Input
                value={form.branch}
                onChange={(e) => update({ branch: e.target.value })}
                placeholder="main or v1.2.0 (e.g., main, master, release/v2.0)"
              />
            </label>
          )}
        </div>
      )}
      {form.input_mode === "upload" && (
        <div className="space-y-3">
          {form.artifact_id ? (
            <div className="flex items-center justify-between gap-3 rounded-md border border-emerald-500/30 bg-emerald-500/10 p-3 text-sm">
              <span className="flex min-w-0 flex-col gap-0.5 font-medium">
                <span className="flex items-center gap-2">
                  <CheckCircle2 className="size-4 shrink-0 text-emerald-400" aria-hidden="true" />
                  <span className="break-all">{form.artifact_name}</span>
                </span>
                <span className="pl-6 text-xs font-normal text-muted-foreground">
                  {(form.artifact_format || artifactFormatFromName(form.artifact_name))} · {formatBytes(form.artifact_size_bytes)} · uploaded artifact — the original bytes reach the scanner
                </span>
              </span>
              <button
                type="button"
                onClick={onClearUpload}
                className="shrink-0 rounded-md border border-border px-2 py-1 text-xs font-semibold text-muted-foreground hover:bg-muted hover:text-foreground"
              >
                Replace
              </button>
            </div>
          ) : (
            <label className="flex cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-border p-6 text-center transition-colors hover:border-primary hover:bg-primary/5">
              <Package className="size-6 text-muted-foreground" aria-hidden="true" />
              <span className="text-sm font-semibold">
                {uploading ? "Uploading artifact…" : spec.uploadCta}
              </span>
              <span className="text-xs text-muted-foreground">Max 64 MiB · never executed</span>
              <input
                type="file"
                className="sr-only"
                accept={spec.accept || undefined}
                disabled={uploading}
                onChange={(e) => {
                  onFileSelected(e.target.files?.[0]);
                  e.target.value = "";
                }}
              />
              {uploading && <Loader2 className="size-4 animate-spin text-primary" aria-hidden="true" />}
            </label>
          )}
          <p className="text-xs leading-5 text-muted-foreground">{spec.uploadHint}</p>
          {spec.showBranch && form.artifact_id && (
            <p className="text-xs text-muted-foreground">Branch selection does not apply to uploaded archives.</p>
          )}
        </div>
      )}
      {form.input_mode === "local" && (
        <div className="space-y-3">
          <label className="flex flex-col gap-2 text-sm font-medium">
            {spec.localLabel || "Server-local path"}
            <Input
              value={form.repository}
              onChange={(e) => update({ repository: e.target.value })}
              placeholder={spec.localPlaceholder}
            />
          </label>
          <p className="text-xs leading-5 text-muted-foreground">{spec.localHint}</p>
        </div>
      )}
      {form.input_mode === "reference" && (
        <div className="space-y-3">
          <label className="flex flex-col gap-2 text-sm font-medium">
            Container image reference
            <Input
              value={form.repository}
              onChange={(e) => update({ repository: e.target.value })}
              placeholder={spec.referencePlaceholder}
            />
          </label>
          <p className="text-xs leading-5 text-muted-foreground">{spec.referenceHint}</p>
        </div>
      )}
      {form.input_mode === "arn" && (
        <div className="space-y-3">
          <label className="flex flex-col gap-2 text-sm font-medium">
            KMS key identifier (ARN / Azure / GCP)
            <Input
              value={form.repository}
              onChange={(e) => update({ repository: e.target.value })}
              placeholder={spec.arnPlaceholder}
            />
          </label>
          <p className="text-xs leading-5 text-muted-foreground">
            {spec.arnHint || "Only the key identifier is recorded. Key material is never requested or accessed."}
          </p>
        </div>
      )}
      <Alert className="bg-muted/50">
        <Info className="text-primary" />
        <span>Static inspection only — QRYPTON does not execute, deploy, or modify the target.</span>
      </Alert>
    </div>
  );
}

function Field({ label, value, onChange, placeholder }: { label: string; value: string; onChange: (value: string) => void; placeholder?: string }) { return <label className="flex flex-col gap-2 text-sm font-medium">{label}<Input value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} /></label>; }
function Select({ label, value, options, onChange }: { label: string; value: string; options: string[]; onChange: (value: string) => void }) { return <label className="flex flex-col gap-2 text-sm font-medium">{label}<select className="h-9 rounded-md border border-border bg-card px-3 text-sm" value={value} onChange={(e) => onChange(e.target.value)}>{options.map((v) => <option key={v}>{v}</option>)}</select></label>; }
function NumberField({ label, value, onChange }: { label: string; value: number; onChange: (value: number) => void }) { return <label className="flex flex-col gap-2 text-xs font-medium">{label} (years)<Input type="number" min="0" value={value} onChange={(e) => onChange(Number(e.target.value) || 0)} /></label>; }
