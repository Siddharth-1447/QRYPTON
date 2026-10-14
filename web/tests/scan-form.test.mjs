import assert from "node:assert/strict";
import { test } from "node:test";
import { clearScanTarget } from "../src/lib/scan-form.ts";

for (const target_type of ["source_repo", "source_archive", "binary", "dependency_manifest", "container_image", "cloud_kms"]) {
  test(`completed ${target_type} clears consumed target without changing business context`, () => {
    const form = Object.freeze({
      target_type, input_mode: "upload", repository: "upload://previous-target",
      branch: "release", artifact_id: "previous-target", artifact_name: "source.zip",
      artifact_format: "zip", artifact_size_bytes: 512, artifact_content_type: "application/zip",
      system_name: "payments", owner: "security", environment: "production",
      data_lifetime: 7, migration_time: 4, crqc_horizon: 8,
    });
    const next = clearScanTarget(form);
    assert.equal(next.repository, "");
    assert.equal(next.branch, "");
    assert.equal(next.artifact_id, null);
    assert.equal(next.artifact_name, "");
    assert.equal(next.artifact_size_bytes, null);
    assert.equal(next.artifact_format, "");
    assert.equal(next.artifact_content_type, "");
    assert.equal(next.target_type, target_type);
    assert.equal(next.input_mode, form.input_mode);
    for (const key of ["system_name", "owner", "environment", "data_lifetime", "migration_time", "crqc_horizon"]) {
      assert.equal(next[key], form[key]);
    }
    assert.equal(form.repository, "upload://previous-target");
  });
}
