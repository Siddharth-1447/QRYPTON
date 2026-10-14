/** Clear consumed target inputs while retaining the selected surface and business context. */
export function clearScanTarget<T extends {
  repository: string;
  branch: string;
  artifact_id: string | null;
  artifact_name: string;
  artifact_format: string;
  artifact_size_bytes: number | null;
  artifact_content_type: string;
}>(form: T): T {
  return {
    ...form,
    repository: "",
    branch: "",
    artifact_id: null,
    artifact_name: "",
    artifact_format: "",
    artifact_size_bytes: null,
    artifact_content_type: "",
  };
}
