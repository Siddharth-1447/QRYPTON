"use client";

import { Wordmark } from "./logo";

import { GlossaryText } from "@/components/glossary";
import { useEffect, useRef, useState } from "react";
import { AlertCircle, ArrowLeft, ArrowRight, CheckCircle2, Loader2, Info, Package, X } from "lucide-react";
import { Alert, RiskBadge, Button, Card, CardContent, CardHeader, CardTitle, Input } from "@/components/ui/primitives";
import { BUSINESS_PRESETS, UNKNOWN_CONTEXT, parseBusinessContext } from "@/lib/business-context";
import { ScanProgress } from "@/components/scan-progress";
import { getScanPhaseMessage, type ScanStatus } from "@/lib/scan-polling";
import { API_BASE } from "@/lib/api";
import type { ReportChoice } from "@/lib/scan-download";

export type ScanInputMode = "url" | "upload" | "local" | "arn" | "reference";

export type ScanForm = {
  report_download?: ReportChoice;
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
  environment: string; business_criticality: string; data_sensitivity: string; data_lifetime: number | null;
  internet_exposure: boolean | null; regulatory_relevance: string; migration_complexity: string;
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
  environment: "unclassified",
  business_criticality: "unclassified",
  data_sensitivity: "unclassified",
  data_lifetime: null,
  internet_exposure: null,
  regulatory_relevance: "unclassified",
  migration_complexity: "unclassified",
  migration_time: 4.0,
  crqc_horizon: 8.0,
};

const MAX_UPLOAD_BYTES = 64 * 1024 * 1024;
type Props = {
  progress?: ScanStatus | null;
  open: boolean;
  onClose: () => void;
  form: ScanForm;
  setForm: (form: ScanForm) => void;
  onSubmit: () => Promise<void>;
  onReset: () => void;
  submitting: boolean;
  successMessage: string | null;
  submitError?: string | null;
  polling?: boolean;
  phaseMessage?: string | null;
  elapsedMs?: number;
  onShowResults?: () => void;
};

export function formatElapsedTime(ms: number): string {
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remSec = seconds % 60;
  return `${minutes}m ${remSec}s`;
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
      "Static inspection only · no execution · status monitoring for up to 15 minutes",
    ],
    ["Mosca", `X ${form.data_lifetime ?? "Unknown / Not provided"} + Y ${form.migration_time} vs Z ${form.crqc_horizon}`]
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

export function ScanWorkflow({ progress = null, open, onClose, form, setForm, onSubmit, onReset, submitting, successMessage, submitError, polling, phaseMessage, elapsedMs, onShowResults }: Props) {
  const scrollToResults = () => {
    if (onShowResults) {
      onShowResults();
      return;
    }
    document.getElementById("results-section")?.scrollIntoView({ behavior: "instant", block: "start" });
  };
  const [step, setStep] = useState(1);
  const [error, setError] = useState<string | null>(null);
  const [executionError, setExecutionError] = useState<string | null>(null);
  const [localElapsedMs, setLocalElapsedMs] = useState(0);
  // Tick a local elapsed clock while the scan is running so the live status
  // message stays fresh even between polling callbacks.
  useEffect(() => {
    if (!submitting && !polling) return;
    const startedAt = Date.now() - (elapsedMs ?? 0);
    const timer = window.setInterval(() => {
      setLocalElapsedMs(Date.now() - startedAt);
    }, 500);
    return () => window.clearInterval(timer);
  }, [submitting, polling, elapsedMs]);
  const effectiveElapsedMs = elapsedMs ?? localElapsedMs;
  const livePhaseMessage = phaseMessage ?? getScanPhaseMessage(effectiveElapsedMs);
  const contextRevision = useRef(0);
  const previousContextTarget = useRef("");
  const update = (patch: Partial<ScanForm>) => {
    contextRevision.current += 1;
    setForm({ ...form, ...patch });
  };
  const [suggestionLabel, setSuggestionLabel] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);
  const spec = specForTarget(form.target_type);
  const incomplete = form.data_lifetime === null || !form.system_name || !form.owner || form.environment === "unclassified" || form.business_criticality === "unclassified" || form.data_sensitivity === "unclassified" || form.regulatory_relevance === "unclassified" || form.migration_complexity === "unclassified" || form.internet_exposure === null;
  const exposed = (form.data_lifetime ?? 0) + form.migration_time > form.crqc_horizon;
  /** Switching target types resets the artifact inputs so a repo link can never leak into KMS/binary flows. */
  const selectTargetType = (targetType: string) => {
    contextRevision.current += 1;
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
    contextRevision.current += 1;
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
        signal: AbortSignal.timeout(30_000),
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
    if ([form.data_lifetime, form.migration_time, form.crqc_horizon].some((v) => v !== null && (!Number.isFinite(v) || v < 0 || v > 10000))) return "Horizon values must be between 0 and 10,000 years.";
    return null;
  };
  const [loadingContext, setLoadingContext] = useState(false);
  const next = async () => {
    if (loadingContext) return;
    const revision = contextRevision.current;
    const targetKey = JSON.stringify([form.target_type, form.repository.trim(), form.branch]);
    const issue = validate();
    if (issue) { setError(issue); return; }
    setError(null);
    if (step === 2 && targetKey !== previousContextTarget.current) {
      setLoadingContext(true);
      setSuggestionLabel(null);
      try {
        const params = new URLSearchParams({ target_type: form.target_type, repository: form.repository.trim(), branch: form.branch });
        const response = await fetch(`${API_BASE}/api/v1/scan-context?${params}`, { signal: AbortSignal.timeout(5000), cache: "no-store" });
        if (!response.ok) throw new Error("Context lookup unavailable");
        const context = parseBusinessContext((await response.json()).context);
        if (revision !== contextRevision.current) return;
        previousContextTarget.current = targetKey;
        setForm({ ...form, ...(context ?? UNKNOWN_CONTEXT) });
        if (context) setSuggestionLabel("Suggested from previous scan");
      } catch {
        if (revision !== contextRevision.current) return;
        setForm({ ...form, ...UNKNOWN_CONTEXT });
        setSuggestionLabel("Previous context unavailable. Choose a preset or enter context below.");
      } finally { setLoadingContext(false); }
    }
    if (revision === contextRevision.current) setStep((v) => v + 1);
  };
  const visibleError = error || executionError || submitError;
  // Field validation keeps the editable wizard visible; only a submitted run can halt.
  const isFailed = Boolean(executionError || submitError);

  const stage = successMessage && !isFailed ? stages.length : submitting || polling || isFailed ? 0 : null;

  useEffect(() => {
    if (!open) {
      // eslint-disable-next-line react-hooks/set-state-in-effect -- reset wizard when modal closes
      setStep(1);
      contextRevision.current += 1;
      previousContextTarget.current = "";
      setError(null);
      setExecutionError(null);
      setLocalElapsedMs(0);
    }
  }, [open]);

  const start = async () => {
    const issue = validate();
    if (issue) return setError(issue);
    setError(null);
    setExecutionError(null);
    setLocalElapsedMs(0);
    try {
      await onSubmit();
    } catch (err) {
      setExecutionError(err instanceof Error ? err.message : "Scan failed.");
    }
  };
  const close = () => { setStep(1); setError(null); onClose(); };
  const back = () => {
    if (submitting || polling || uploading) return;
    setError(null);
    setExecutionError(null);
    if (isFailed || successMessage) {
      onReset();
      setLocalElapsedMs(0);
      setStep(2);
    } else if (step === 1) {
      close();
    } else {
      setStep((value) => value - 1);
    }
  };
  if (!open) return null;
  const isWorkflowActive = stage !== null || isFailed;

  return <div className="fixed inset-0 z-50 flex items-center justify-center p-4" role="dialog" aria-modal="true"><button className="absolute inset-0 bg-foreground/40 backdrop-blur-sm" aria-label="Close" onClick={close} /><Card className="relative flex max-h-[calc(100vh-2rem)] w-full max-w-3xl flex-col overflow-hidden bg-card"><CardHeader className="border-b border-border p-6"><div className="flex justify-between gap-4"><div><CardTitle>New Cryptographic Scan</CardTitle><p className="mt-1 text-sm text-muted-foreground">Static inspection only—<Wordmark /> does not execute, deploy, or modify a target.</p></div><Button variant="ghost" onClick={close}><X /></Button></div><div className="mt-5 flex gap-2 overflow-x-auto">{steps.map((label, i) => <div key={`${label}-${i}`} className="flex items-center gap-2"><span className={`flex size-7 items-center justify-center rounded-full text-xs ${i + 1 === step ? "bg-primary text-primary-foreground" : "border border-border"}`}>{i + 1}</span><span className="text-xs text-muted-foreground">{label}</span></div>)}</div></CardHeader><CardContent className="overflow-y-auto p-6">
    {isWorkflowActive ? <div className="space-y-4">
      <h3 className="font-semibold">{isFailed ? "Scan Needs Attention" : successMessage || "Scan in Progress"}</h3>
      <p role="status" className="text-sm text-muted-foreground">{visibleError || (successMessage ? "Results are ready." : livePhaseMessage)}</p>
      <p className="text-sm text-muted-foreground">You can leave this page. The scan continues in the background and appears in Scan History. Completion notifications appear here when you return.</p>
      <ScanProgress progress={progress} />
      <Button variant="ghost" onClick={close}>Continue in background</Button>
    </div> : <>
    {step === 1 && <div><h3 className="font-semibold">Select Target Type</h3><p className="mt-1 text-sm text-muted-foreground">Select what contains the cryptographic evidence.</p><div className="mt-4 grid gap-4 sm:grid-cols-2">{targetTypes.map(([value, label, note]) => <button key={value} type="button" onClick={() => selectTargetType(value)} className={`rounded-lg border p-4 text-left ${form.target_type === value ? "border-primary bg-primary/5 ring-1 ring-primary" : "border-border hover:bg-muted"}`}><span className="block text-sm font-semibold"><GlossaryText>{label}</GlossaryText></span><span className="mt-1 block text-xs leading-5 text-muted-foreground"><GlossaryText>{note}</GlossaryText></span></button>)}</div></div>}
    {step === 2 && <TargetInputs form={form} update={update} spec={spec} uploading={uploading} onSelectMode={selectInputMode} onFileSelected={(file) => void onFileSelected(file)} onClearUpload={onClearUpload} />}
    {step === 3 && <div className="space-y-4"><h3 className="font-semibold">Business Context</h3>
      <p className="text-sm text-muted-foreground">Choose a starting point. All values remain editable; lifetime is in years.</p>
      <div className="flex flex-wrap gap-2">{Object.entries(BUSINESS_PRESETS).map(([name, context]) => <Button key={name} variant="secondary" onClick={() => { update(context); setSuggestionLabel(`Template: ${name}`); }}>{name}</Button>)}<Button variant="ghost" onClick={() => { update(UNKNOWN_CONTEXT); setSuggestionLabel(null); }}>Unknown / Not provided</Button></div>
      {suggestionLabel && <p role="status" className="text-sm text-secondary">{suggestionLabel}</p>}<div className="grid gap-4 sm:grid-cols-2"><Field label="System name" value={form.system_name} onChange={(v) => update({ system_name: v })} placeholder="e.g. payments-core" /><Field label="Owner" value={form.owner} onChange={(v) => update({ owner: v })} placeholder="e.g. team-crypto" /><Select label="Environment" value={form.environment} options={["production", "staging", "development"]} onChange={(v) => update({ environment: v })} /><Select label="Business criticality" value={form.business_criticality} options={["critical", "high", "medium", "low"]} onChange={(v) => update({ business_criticality: v })} /><Select label="Data sensitivity" value={form.data_sensitivity} options={["restricted", "confidential", "internal", "public"]} onChange={(v) => update({ data_sensitivity: v })} /><Select label="Regulatory relevance" value={form.regulatory_relevance} options={["regulated", "contractual", "none"]} onChange={(v) => update({ regulatory_relevance: v })} /><Select label="Migration complexity" value={form.migration_complexity} options={["high", "medium", "low"]} onChange={(v) => update({ migration_complexity: v })} /><Select label="Internet exposure" value={form.internet_exposure === null ? "unclassified" : form.internet_exposure ? "yes" : "no"} options={["yes", "no"]} onChange={(v) => update({ internet_exposure: v === "unclassified" ? null : v === "yes" })} /></div><div className="rounded-lg border border-border bg-muted/40 p-4"><div className="flex justify-between"><span className="text-sm font-semibold"><GlossaryText>{"Mosca urgency: X + Y vs Z"}</GlossaryText></span><span className="flex flex-wrap items-center gap-2"><RiskBadge level={form.data_lifetime == null || form.migration_time == null || form.crqc_horizon == null ? "unknown" : exposed ? "critical" : "safe"} /><span className="text-xs text-muted-foreground">{form.data_lifetime == null || form.migration_time == null || form.crqc_horizon == null ? "Enter timeline inputs" : exposed ? "Urgent" : "Within horizon"}</span></span></div><div className="mt-3 grid gap-4 sm:grid-cols-3"><NumberField label="Data lifetime X" value={form.data_lifetime} onChange={(v) => update({ data_lifetime: v })} placeholder="Unknown / Not provided" /><NumberField label="Migration effort Y" value={form.migration_time} onChange={(v) => update({ migration_time: v ?? 0 })} placeholder="e.g. 2" /><NumberField label="CRQC horizon Z" value={form.crqc_horizon} onChange={(v) => update({ crqc_horizon: v ?? 0 })} placeholder="e.g. 10" /></div></div>{incomplete && <Alert className="border-border bg-muted"><AlertCircle className="text-secondary" /><span>Business context incomplete: prioritization confidence reduced</span></Alert>}</div>}
    {step === 4 && <div className="space-y-4"><h3 className="font-semibold">Review Scope and Limits</h3><fieldset className="rounded-lg border border-border p-4"><label className="flex items-center gap-3 text-sm font-medium"><input type="checkbox" checked={!!form.report_download && form.report_download !== "none"} onChange={event => setForm({ ...form, report_download: event.target.checked ? "pdf" : "none" })} />Download reports when this scan finishes</label>{form.report_download && form.report_download !== "none" && <div className="mt-3"><label className="flex flex-col gap-2 text-sm">Report Format<select value={form.report_download} onChange={event => setForm({ ...form, report_download: event.target.value as ReportChoice })} className="rounded-md border border-input bg-card p-2"><option value="pdf">PDF report</option><option value="json">JSON CBOM</option><option value="csv">CSV inventory</option><option value="all">All — PDF, JSON, and CSV</option></select></label><p className="mt-2 text-xs text-muted-foreground">Downloads use only this scan’s saved results. For All, allow multiple downloads in your browser. You can also download them later from Results.</p></div>}</fieldset>{incomplete && <p role="status" className="text-sm text-muted-foreground">Business context incomplete: prioritization confidence reduced</p>}<div className="divide-y divide-border rounded-lg border border-border">{buildReviewRows(form).map(([label, value]) => <div key={label} className="flex justify-between gap-4 p-4 text-sm"><span className="text-muted-foreground"><GlossaryText>{label}</GlossaryText></span><span className="text-right font-medium break-all"><GlossaryText>{value}</GlossaryText></span></div>)}</div></div>}</>}{visibleError && <Alert className="mt-4 border-input bg-muted"><AlertCircle className="text-secondary" /><span>{visibleError}</span></Alert>}</CardContent><div className="flex justify-between border-t border-border p-6"><Button variant="ghost" onClick={back} disabled={submitting || polling || uploading || loadingContext}><ArrowLeft />{isFailed ? "Back to target" : successMessage ? "New scan" : step === 1 ? "Cancel" : "Back"}</Button>{stage === null && !isFailed && (step < 4 ? <Button onClick={next} disabled={uploading || loadingContext}>{loadingContext ? "Looking up previous context…" : uploading ? "Uploading…" : <>Continue <ArrowRight /></>}</Button> : <Button onClick={start} disabled={submitting || uploading}><Package />{uploading ? "Uploading…" : "Start scan"}</Button>)}{stage === stages.length && !isFailed && <div className="flex items-center gap-2"><Button variant="ghost" onClick={close}>Close</Button><Button onClick={scrollToResults}>Show Results <ArrowRight /></Button></div>}</div></Card></div>;
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
  const [dragActive, setDragActive] = useState(false);
  return (
    <div className="space-y-4">
      <div>
        <h3 className="font-semibold">{spec.title}</h3>
        <p className="mt-1 text-sm text-muted-foreground"><GlossaryText>{spec.subtitle}</GlossaryText></p>
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
              className={`rounded-full border px-4 py-1.5 text-xs font-semibold qrypton-motion ${
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
        <div className="space-y-4">
          <label className="flex flex-col gap-2 text-sm font-medium">
            Repository URL
            <Input
              className="font-mono"
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
        <div className="space-y-4">
          {form.artifact_id ? (
            <div className="flex items-center justify-between gap-4 rounded-md border border-border bg-muted p-4 text-sm">
              <span className="flex min-w-0 flex-col gap-0.5 font-medium">
                <span className="flex items-center gap-2">
                  <CheckCircle2 className="size-4 shrink-0 text-secondary" aria-hidden="true" />
                  <span className="break-all font-mono font-normal">{form.artifact_name}</span>
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
            <label
              className={`flex cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border border-dashed p-6 text-center qrypton-motion ${dragActive ? "border-primary bg-primary/10" : "border-border hover:border-primary hover:bg-primary/5"}`}
              onDragOver={(e) => { e.preventDefault(); if (!uploading) setDragActive(true); }}
              onDragLeave={() => setDragActive(false)}
              onDrop={(e) => {
                e.preventDefault();
                setDragActive(false);
                if (uploading) return;
                const file = e.dataTransfer.files?.[0];
                if (file) onFileSelected(file);
              }}
            >
              <Package className="size-6 text-muted-foreground" aria-hidden="true" />
              <span className="text-sm font-semibold">
                {uploading ? "Uploading artifact…" : dragActive ? "Drop file to upload" : spec.uploadCta}
              </span>
              <span className="text-xs text-muted-foreground">Drag &amp; drop or click to browse · Max 64 MiB · never executed</span>
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
              {uploading && <Loader2 className="size-4  text-secondary" aria-hidden="true" />}
            </label>
          )}
          <p className="text-xs leading-5 text-muted-foreground">{spec.uploadHint}</p>
          {spec.showBranch && form.artifact_id && (
            <p className="text-xs text-muted-foreground">Branch selection does not apply to uploaded archives.</p>
          )}
        </div>
      )}
      {form.input_mode === "local" && (
        <div className="space-y-4">
          <label className="flex flex-col gap-2 text-sm font-medium">
            {spec.localLabel || "Server-local path"}
            <Input
              className="font-mono"
              value={form.repository}
              onChange={(e) => update({ repository: e.target.value })}
              placeholder={spec.localPlaceholder}
            />
          </label>
          <p className="text-xs leading-5 text-muted-foreground">{spec.localHint}</p>
        </div>
      )}
      {form.input_mode === "reference" && (
        <div className="space-y-4">
          <label className="flex flex-col gap-2 text-sm font-medium">
            Container image reference
            <Input
              className="font-mono"
              value={form.repository}
              onChange={(e) => update({ repository: e.target.value })}
              placeholder={spec.referencePlaceholder}
            />
          </label>
          <p className="text-xs leading-5 text-muted-foreground">{spec.referenceHint}</p>
        </div>
      )}
      {form.input_mode === "arn" && (
        <div className="space-y-4">
          <label className="flex flex-col gap-2 text-sm font-medium">
            KMS key identifier (ARN / Azure / GCP)
            <Input
              className="font-mono"
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
        <Info className="text-secondary" />
        <span>Static inspection only — <Wordmark /> does not execute, deploy, or modify the target.</span>
      </Alert>
    </div>
  );
}

function Field({ label, value, onChange, placeholder }: { label: string; value: string; onChange: (value: string) => void; placeholder?: string }) { return <label className="flex flex-col gap-2 text-sm font-medium">{label}<Input value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} /></label>; }
function Select({ label, value, options, onChange }: { label: string; value: string; options: string[]; onChange: (value: string) => void }) { return <label className="flex flex-col gap-2 text-sm font-medium">{label}<select className="h-10 rounded-md border border-border bg-card px-4 text-sm" value={value} onChange={(e) => onChange(e.target.value)}>{["Business criticality", "Environment", "Data sensitivity", "Regulatory relevance", "Migration complexity", "Internet exposure"].includes(label) && <option value="unclassified">Unknown / Not provided</option>}{options.map((v) => <option key={v}>{v}</option>)}</select></label>; }
function NumberField({ label, value, onChange, placeholder }: { label: string; value: number | null; onChange: (value: number | null) => void; placeholder?: string }) { return <label className="flex flex-col gap-2 text-xs font-medium">{label} (years)<Input type="number" min="0" value={value ?? ""} placeholder={placeholder} onChange={(e) => { const val = e.target.value; if (val === "") { onChange(null); } else { const num = Number(val); onChange(isNaN(num) ? null : num); } }} /></label>; }
