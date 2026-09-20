/**
 * DNS-pinned outbound connections for tenant-supplied Coolify addresses.
 *
 * ## The gap this closes
 *
 * `probeCoolify` (enroll.ts) validates a tenant's base URL once, at enrolment
 * time, using the upstream SSRF guard's three checks. Every tool call after
 * that runs against the same stored `baseUrl` through `CoolifyClient`, which —
 * for the single-tenant server this codebase was built for — calls the global
 * `fetch()` with no DNS pinning at all. That is correct there: the base URL is
 * operator configuration, chosen by whoever deployed the container, and
 * upstream's SSRF guard says so explicitly (`ssrf.ts`: "The Coolify base URL
 * is deliberately NOT routed through here. It is operator configuration").
 *
 * In multi-tenant mode the base URL is nothing of the sort — it is supplied by
 * a stranger, stored, and replayed on every subsequent tool call, by a server
 * sitting inside this cluster's network. A tenant who controls a domain can
 * enroll it while it points at a public Coolify, pass the enrolment probe, and
 * then repoint its DNS at an internal address — Vault, the Kubernetes API,
 * another tenant's service — for a later request. The enrolment-time check
 * cannot see that: it runs once, long before the request it is meant to guard.
 *
 * ## Why per-request, not per-tenant
 *
 * Nothing here is cached, for the same reason `registryForCaller` caches
 * nothing: a cached resolution is exactly the rebinding window this exists to
 * close, just moved from "between enrolment and first use" to "between one
 * cache refresh and the next." `createMcpHandler` already builds one
 * `CoolifyMcpServer` per HTTP request, so re-resolving here costs one extra
 * DNS lookup per request — the same trade `registryForCaller` already makes
 * for its Vault read, made explicit there as "correctness is worth it."
 *
 * ## Why an Agent, not a plain fetch option
 *
 * Node's global `fetch()` has no `lookup` option of its own — that belongs to
 * `http.request`/`https.request`, which is what upstream's own SSRF-guarded
 * fetch (`ssrf.ts`) uses instead of `fetch()`. A per-request `undici` `Agent`
 * with a pinned `connect.lookup` carries the same `pinnedLookup` this
 * codebase already trusts into a `fetch()`-shaped call. Its idle sockets
 * close on undici's own default keep-alive timeout once the request that
 * created it is done; nothing here holds a longer-lived pool.
 *
 * This `Agent` is a standalone-`undici`-package object, a different build
 * from whatever `undici` Node bundles internally for the global `fetch()` —
 * the two have an internal request-handler ABI that has broken across major
 * versions before. `CoolifyClient` must consume this dispatcher through
 * `undici`'s own `fetch` export, never the global one, or every call throws
 * `UND_ERR_INVALID_ARG` before opening a socket. See `coolify-client.ts`'s
 * `doFetch`.
 */
import type { Dispatcher } from 'undici';
import { assertPublicUrl, pinnedLookup, resolvePublicAddresses, type Resolver } from './ssrf.js';

export { UnsafeUrlError } from './ssrf.js';

/**
 * Validate a tenant-supplied base URL and return a dispatcher pinned to the
 * addresses it resolved to right now. Throws `UnsafeUrlError` (re-exported
 * above) on anything the guard refuses — the caller decides how to surface
 * that to whoever is waiting on the tool call.
 */
export async function pinnedDispatcherFor(
  baseUrl: string,
  options: { resolver?: Resolver } = {},
): Promise<Dispatcher> {
  const url = assertPublicUrl(baseUrl);
  const addresses = await resolvePublicAddresses(url.hostname, options.resolver);
  // Deferred: `undici` requires Node >=22.19 (its CacheStorage shim needs a
  // webidl helper older runtimes don't have). A static top-level import would
  // crash single-tenant and stdio users on Node 20 the moment this *module*
  // loads, even though they never call this function — multi-tenant mode is
  // the only caller.
  const { Agent } = await import('undici');
  return new Agent({ connect: { lookup: pinnedLookup(addresses) } });
}
