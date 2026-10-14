import assert from "node:assert/strict";
import { test } from "node:test";
import { BUSINESS_PRESETS, UNKNOWN_CONTEXT, parseBusinessContext } from "../src/lib/business-context.ts";

test("every named preset fills all four fields and remains independently editable", () => {
  const expected = [
    ["Payment gateway", "critical", "restricted", 7, true],
    ["Internal tool", "medium", "internal", 1, false],
    ["Patient records", "critical", "restricted", 30, false],
    ["Public marketing site", "medium", "public", 1, true],
  ];
  for (const [name, criticality, sensitivity, lifetime, exposure] of expected) {
    const form = { ...BUSINESS_PRESETS[name] };
    assert.deepEqual(Object.values(form), [criticality, sensitivity, lifetime, exposure]);
    form.data_lifetime = 5;
    assert.equal(BUSINESS_PRESETS[name].data_lifetime, lifetime);
  }
});

test("unknown context is explicit and never low risk or zero years", () => {
  assert.deepEqual(parseBusinessContext(UNKNOWN_CONTEXT), UNKNOWN_CONTEXT);
  assert.equal(UNKNOWN_CONTEXT.data_lifetime, null);
  assert.equal(UNKNOWN_CONTEXT.internet_exposure, null);
  assert.equal(UNKNOWN_CONTEXT.business_criticality, "unclassified");
});

test("previous context is validated and cannot replace target fields", () => {
  assert.deepEqual(parseBusinessContext({ ...BUSINESS_PRESETS["Patient records"], repository: "wrong" }), BUSINESS_PRESETS["Patient records"]);
  for (const value of [null, {}, { ...UNKNOWN_CONTEXT, data_lifetime: -1 }, { ...UNKNOWN_CONTEXT, internet_exposure: "false" }, { ...UNKNOWN_CONTEXT, data_lifetime: NaN }]) {
    assert.equal(parseBusinessContext(value), null);
  }
  assert.equal(parseBusinessContext({ ...UNKNOWN_CONTEXT, data_lifetime: 0 }).data_lifetime, 0);
});
