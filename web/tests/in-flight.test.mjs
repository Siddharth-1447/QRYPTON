import assert from 'node:assert/strict';
import test from 'node:test';
import { inFlight } from '../src/lib/in-flight.ts';

test('concurrent readers share one request; completed values are never cached', async () => {
  let complete;
  let requests = 0;
  const read = () => { requests++; return new Promise(resolve => { complete = resolve; }); };
  const first = inFlight('scan-a', read);
  const second = inFlight('scan-a', read);
  assert.equal(first, second);
  complete({ count: 42 });
  assert.deepEqual(await first, { count: 42 });
  const fresh = inFlight('scan-a', read);
  complete({ count: 43 });
  assert.deepEqual(await fresh, { count: 43 });
  assert.equal(requests, 2);
});

test('a failed request can be retried and different scans remain independent', async () => {
  const failed = inFlight('failed-scan', async () => { throw new Error('offline'); });
  await assert.rejects(failed, /offline/);
  assert.equal(await inFlight('failed-scan', async () => 1), 1);
  const [a, b] = await Promise.all([inFlight('scan-a', async () => 'a'), inFlight('scan-b', async () => 'b')]);
  assert.deepEqual([a, b], ['a', 'b']);
});
