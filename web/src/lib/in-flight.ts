/** Share concurrent reads without caching settled data or failures. */
const pending = new Map<string, Promise<unknown>>();

export function inFlight<T>(key: string, request: () => Promise<T>): Promise<T> {
  const existing = pending.get(key);
  if (existing) return existing as Promise<T>;
  const task = request();
  pending.set(key, task);
  const release = () => { if (pending.get(key) === task) pending.delete(key); };
  void task.then(release, release);
  return task;
}
