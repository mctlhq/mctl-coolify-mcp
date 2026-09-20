/**
 * The standalone `undici` npm package (pinned to 8.x) requires Node >=22.19
 * — its `CacheStorage` shim needs `webidl.util.markAsUncloneable`, added in
 * that release. `tenant-dispatcher.ts`'s `pinnedDispatcherFor` defers its
 * `import('undici')` to the one function that needs it so single-tenant and
 * stdio mode stay Node-20-safe (see its own comment), but any test that
 * actually calls `pinnedDispatcherFor` — directly, or through
 * `registryForCaller` — still hits that import and crashes the same way on
 * an older runtime.
 *
 * Guard such a test with `(undiciNodeSupported() ? it : it.skip)(...)` so
 * CI's Node 20.x leg skips it instead of failing red for a constraint the
 * test itself can't change.
 */
export function undiciNodeSupported(): boolean {
  const [major, minor] = process.versions.node.split('.').map(Number);
  return major > 22 || (major === 22 && minor >= 19);
}
