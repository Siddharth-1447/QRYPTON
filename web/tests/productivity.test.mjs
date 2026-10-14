import test from 'node:test';
import assert from 'node:assert/strict';
import { matchesQuickQuery, GLOSSARY } from '../src/lib/productivity.ts';

test('quick search combines exposure, algorithm and risk rather than phrase matching', () => {
  const row = { finding_id: 'f', algorithm_name: 'rsa', risk_level: 'critical', application: 'payments', observations: { exposure: { state: 'observed', value: true } } };
  assert.equal(matchesQuickQuery(row, 'internet-facing RSA critical'), true);
  assert.equal(matchesQuickQuery(row, 'RSA high'), false);
  assert.equal(matchesQuickQuery({ ...row, observations: { exposure: { state: 'unknown', value: true } } }, 'internet-facing'), false);
  assert.equal(matchesQuickQuery(row, 'payments RSA'), true);
});
test('all required glossary terms have concise definitions with distinct cryptographic roles', () => {
  assert.equal(Object.keys(GLOSSARY).length, 7);
  for (const value of Object.values(GLOSSARY)) assert.ok(value.length < 210);
  assert.match(GLOSSARY['ML-KEM'], /shared secret key/);
  assert.match(GLOSSARY['ML-DSA'], /digital signature/);
  assert.match(GLOSSARY['SLH-DSA'], /hash-based/);
});
