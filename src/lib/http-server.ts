/**
 * Streamable HTTP mode (#303): web-standard request router wiring the SDK's
 * protected-resource pieces (createMcpHandler, requireBearerAuth, metadata)
 * to the OAuth 2.1 authorization server in `oauth.ts`.
 *
 * Everything here is fetch-shaped (Request in, Response out) so it runs
 * unchanged under any web-standard host; `http.ts` provides the thin Node
 * adapter. No framework, no cookies, no sessions — the authorize form is the
 * only HTML and carries its whole state in the form body.
 *
 * Browser requests to `GET /` receive the landing page from `public/`.
 */

import { readFile } from 'node:fs/promises';
import { join, normalize, dirname, extname, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  createMcpHandler,
  requireBearerAuth,
  type McpHttpHandler,
} from '@modelcontextprotocol/server';
import { CoolifyMcpServer } from './mcp-server.js';
import { OAuthProvider, OAuthErrorResponse, isClientIdUrl } from './oauth.js';
import type { CoolifyConfig } from '../types/coolify.js';
import type { InstanceRegistry } from './instances.js';
import {
  configuredProviders,
  exchangeCodeForIdentity,
  loginRedirectUrl,
  openEnrolmentTicket,
  openLoginState,
  sealEnrolmentTicket,
  sealLoginState,
  IdentityError,
  type IdentityConfig,
  type Provider,
  type VerifiedIdentity,
} from './identity.js';
import {
  NotEnrolledError,
  registryForCaller,
  subjectFromAuthInfo,
  type TenantRecord,
  type TenantStore,
} from './tenancy.js';
import { enrollPage, isValidInstanceName, normalizeBaseUrl, probeCoolify } from './enroll.js';

/**
 * Multi-tenant mode. Absent means the upstream single-tenant server: the
 * container's own credential serves every caller, and the authorize form asks
 * for proof of access to that one instance.
 */
export interface TenancyConfig {
  store: TenantStore;
  identity: IdentityConfig;
  /**
   * Outbound addresses, shown only to a logged-in tenant who needs them for
   * Coolify's "Allowed API IPs". Never put these in public documentation: this
   * server sits behind a CDN, and publishing them hands over the origin.
   */
  egressAddresses?: string[];
  /**
   * Overrides the real `probeCoolify` — dependency injection, not mocking, in
   * the same shape as `resolver` and `now` elsewhere in this codebase. The
   * real probe needs a live https Coolify to answer; this is what lets the
   * rest of the enrolment route (ticket verification, form handling, the
   * store, the redirect back into the OAuth flow) be tested without one.
   */
  probe?: typeof probeCoolify;
}

export interface HttpServerConfig {
  /**
   * The default instance: what tier-2 proof of access validates against.
   *
   * Optional, because multi-tenant mode has no such instance — the operator of
   * a hosted server need not own a Coolify at all, and every caller brings
   * their own. Required in single-tenant mode, where it is the whole server.
   */
  coolify?: CoolifyConfig;
  /** The full fleet (#367); omitted means `coolify` alone. */
  instances?: InstanceRegistry;
  /** Public base URL of this container, e.g. https://mcp.example.com */
  publicUrl: string;
  accessTokenTtl: number;
  refreshTokenTtl: number;
  stateFile: string;
  readonly: boolean;
  /** Present in multi-tenant mode only. */
  tenancy?: TenancyConfig;
}

/**
 * Accept the shapes MCP_PUBLIC_URL actually arrives in and produce one
 * canonical origin. Coolify's SERVICE_FQDN magic variable has carried both
 * bare domains and full URLs across versions, and a human typing the value
 * will produce trailing slashes and stray whitespace — none of which should
 * be a boot failure. A bare domain is assumed https (the TLS-terminating
 * proxy is the deployment model); anything unparseable throws.
 */
export function normalizePublicUrl(raw: string): string {
  // Parse before any slash-stripping: pre-mangling turns scheme-only garbage
  // like "http://" into something that survives the https-prefix fallback.
  let value = raw.trim();
  if (value === '') throw new Error('empty URL');
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) {
    value = `https://${value}`;
  }
  const url = new URL(value);
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new Error(`unsupported protocol: ${url.protocol}`);
  }
  if (!url.hostname) {
    throw new Error('no hostname');
  }
  // Origin + path (no trailing slash), dropping query/fragment noise.
  return `${url.origin}${url.pathname.replace(/\/+$/, '')}`;
}

/** Where the HTTP listener binds: the argument handed to `server.listen()`. */
export interface ListenOptions {
  port: number;
  host?: string;
}

/**
 * Resolve the listen address from the environment. `MCP_PORT` (or `PORT`)
 * picks the port, exactly as before. `MCP_HOST` picks the interface.
 *
 * Unset or blank means every interface, which is what a container needs: the
 * platform's proxy reaches it over the container network. Run the same server
 * on a workstation and that default puts a process holding a Coolify token on
 * every network the machine joins, so `MCP_HOST=127.0.0.1` keeps it on
 * loopback. The `host` key is left out rather than set to `undefined`, so an
 * unconfigured server binds exactly as it did before this option existed.
 */
export function listenOptionsFromEnv(env: NodeJS.ProcessEnv): ListenOptions {
  const port = Number(env.MCP_PORT || env.PORT || 8080);
  const host = env.MCP_HOST?.trim();
  return host ? { port, host } : { port };
}

/**
 * The address for the startup log line. Unset host keeps the historical
 * `:8080` form that deploy logs and the docs grep for; an IPv6 literal gets
 * brackets so the port stays readable.
 */
export function describeListen({ port, host }: ListenOptions): string {
  if (host === undefined) return `:${port}`;
  return host.includes(':') ? `[${host}]:${port}` : `${host}:${port}`;
}

/**
 * Tier-2 proof of access: does this Coolify API token belong to someone with
 * access to the instance this container manages? `GET /teams/current` 401s on
 * a bad token and returns the token's team on a good one. The token is used
 * for exactly this one request and then discarded — never stored, never used
 * to act.
 */
export async function validateCoolifyToken(
  baseUrl: string,
  presentedToken: string,
  extraHeaders: Record<string, string> = {},
): Promise<{ ok: true; teamName: string } | { ok: false }> {
  try {
    // extraHeaders carries the Cloudflare Access service token (#373) when
    // configured — without it, an Access policy 302s this probe to an SSO
    // page and every authorization fails while /healthz stays green. Spread
    // first so it can never displace the Authorization being proven.
    // `/teams/current`, not the spec's `/team`: the old path is still routed
    // upstream and is the only one on 4.0–4.2 (#347, CLAUDE.md gotcha).
    const response = await fetch(`${baseUrl.replace(/\/$/, '')}/api/v1/teams/current`, {
      headers: {
        ...extraHeaders,
        Authorization: `Bearer ${presentedToken}`,
        Accept: 'application/json',
      },
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) return { ok: false };
    const team = (await response.json()) as { name?: string };
    return { ok: true, teamName: typeof team.name === 'string' ? team.name : 'your team' };
  } catch {
    // Coolify unreachable is a "no": proof of access cannot be established.
    return { ok: false };
  }
}

/**
 * Fixed-window per-IP rate limiter for the endpoints that take guesses
 * (token, register, authorize POST). Deliberately simple: one container
 * serves one team, so the goal is blunting brute force, not fairness.
 */
export class RateLimiter {
  private readonly windows = new Map<string, { count: number; resetAt: number }>();

  constructor(
    private readonly limit: number,
    private readonly windowMs: number,
  ) {}

  allow(key: string): boolean {
    const now = Date.now();
    const window = this.windows.get(key);
    if (!window || window.resetAt < now) {
      // Piggyback stale-entry cleanup on writes so the map cannot grow
      // unbounded across many source IPs.
      if (this.windows.size > 10_000) {
        for (const [k, w] of this.windows) {
          if (w.resetAt < now) this.windows.delete(k);
        }
      }
      this.windows.set(key, { count: 1, resetAt: now + this.windowMs });
      return true;
    }
    window.count += 1;
    return window.count <= this.limit;
  }
}

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers },
  });
}

function oauthError(error: OAuthErrorResponse): Response {
  return json({ error: error.code, error_description: error.description }, error.status);
}

/** A 302 that is never cached: every one of these carries one-time state. */
function redirect(location: string): Response {
  return new Response(null, { status: 302, headers: { location, 'cache-control': 'no-store' } });
}

function html(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' },
  });
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ── landing page and static asset serving ──────────────────────────────────

/**
 * The landing page and static assets live in `public/` at the package root.
 * In the container this is `/app/public/`; locally it is wherever the source
 * checkout is. The path is resolved once at import time.
 */
const publicDir = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'public');

const MIME_TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.txt': 'text/plain; charset=utf-8',
  '.json': 'application/json',
};

/**
 * Serve a file from `public/`, with path traversal protection. Returns null
 * if the file does not exist or the path escapes the root.
 */
async function servePublicFile(
  relativePath: string,
  cacheSeconds = 300,
  method = 'GET',
): Promise<Response | null> {
  // Decode percent-encoded segments to prevent bypasses like %2e%2e
  let decoded: string;
  try {
    decoded = decodeURIComponent(relativePath);
  } catch {
    return null;
  }

  // Normalize and guard: the resolved path must still start with publicDir + sep.
  const safe = normalize(decoded).replace(/^\/+/, '');
  if (safe.split('/').includes('..') || safe.split('\\').includes('..')) return null;
  const absolute = join(publicDir, safe);
  if (!absolute.startsWith(publicDir + sep) && absolute !== publicDir) return null;

  try {
    const ext = extname(safe).toLowerCase();
    const headers: Record<string, string> = {
      'content-type': MIME_TYPES[ext] ?? 'application/octet-stream',
      'cache-control': `public, max-age=${cacheSeconds}`,
      'x-content-type-options': 'nosniff',
    };
    if (method === 'HEAD') {
      return new Response(null, { status: 200, headers });
    }
    const body = await readFile(absolute);
    return new Response(body, {
      status: 200,
      headers,
    });
  } catch {
    return null;
  }
}

/**
 * The authorize page. One credential field, the rest of the OAuth request
 * carried as hidden fields. The form posts back to the same origin; there are
 * no cookies, so there is no ambient authority for CSRF to ride on.
 */
function authorizePage(params: URLSearchParams, clientName: string, error?: string): string {
  const hidden = [...params.entries()]
    .map(
      ([key, value]) =>
        `<input type="hidden" name="${escapeHtml(key)}" value="${escapeHtml(value)}">`,
    )
    .join('\n      ');
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Authorize ${escapeHtml(clientName)}</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 26rem; margin: 12vh auto; padding: 0 1rem; color: #1a1a1a; }
    h1 { font-size: 1.2rem; }
    p { line-height: 1.5; color: #444; }
    label { display: block; font-weight: 600; margin: 1.2rem 0 0.3rem; }
    input[type=password] { width: 100%; padding: 0.6rem; font-size: 1rem; border: 1px solid #bbb; border-radius: 6px; box-sizing: border-box; }
    button { margin-top: 1.2rem; width: 100%; padding: 0.7rem; font-size: 1rem; border: 0; border-radius: 6px; background: #6b16ed; color: #fff; cursor: pointer; }
    .error { background: #fde8e8; border: 1px solid #f5b5b5; border-radius: 6px; padding: 0.6rem 0.8rem; color: #8a1f1f; }
    .note { font-size: 0.85rem; color: #666; }
  </style>
</head>
<body>
  <h1>Authorize ${escapeHtml(clientName)}</h1>
  <p><strong>${escapeHtml(clientName)}</strong> wants to manage your Coolify instance through this MCP server.</p>
  ${error ? `<p class="error">${escapeHtml(error)}</p>` : ''}
  <form method="post" action="authorize">
      ${hidden}
      <label for="coolify_token">Your Coolify API token</label>
      <input type="password" id="coolify_token" name="coolify_token" autocomplete="off" required>
      <p class="note">Used once to prove you have access to this Coolify instance, then discarded.
      It is never stored and never sent to the client. Create one under
      Keys &amp; Tokens &rarr; API tokens in your Coolify dashboard.</p>
      <p class="note"><strong>Before you paste anything:</strong> check the address bar. It should
      show the domain <em>you</em> deployed this MCP server on. Only your own server should ever
      ask for a Coolify token.</p>
      <button type="submit">Authorize</button>
  </form>
</body>
</html>`;
}

const PROVIDER_LABEL: Record<Provider, string> = { github: 'GitHub', google: 'Google' };

/**
 * Shown only when a deployment configures more than one identity provider.
 * The links go straight to `loginRedirectUrl`'s output — a server-computed
 * redirect, not user input — so there is nothing here for an open-redirect
 * check to guard against.
 */
function loginChooserPage(identity: IdentityConfig, providers: Provider[], state: string): string {
  const links = providers
    .map(
      (provider) =>
        `<a class="provider" href="${escapeHtml(loginRedirectUrl(identity, provider, state))}">Continue with ${PROVIDER_LABEL[provider]}</a>`,
    )
    .join('\n      ');
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sign in</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 22rem; margin: 16vh auto; padding: 0 1rem; color: #1a1a1a; }
    h1 { font-size: 1.2rem; }
    .provider { display: block; text-align: center; margin-top: 1rem; padding: 0.7rem; font-size: 1rem; border: 1px solid #bbb; border-radius: 6px; color: #1a1a1a; text-decoration: none; }
    .provider:hover { background: #f4f4f4; }
  </style>
</head>
<body>
  <h1>Sign in to continue</h1>
  ${links}
</body>
</html>`;
}

export function createHttpApp(config: HttpServerConfig): {
  fetch: (request: Request) => Promise<Response>;
  provider: OAuthProvider;
} {
  const publicUrl = config.publicUrl.replace(/\/$/, '');
  const resourceUrl = `${publicUrl}/mcp`;

  const provider = new OAuthProvider({
    issuer: publicUrl,
    resource: resourceUrl,
    accessTokenTtl: config.accessTokenTtl,
    refreshTokenTtl: config.refreshTokenTtl,
    stateFile: config.stateFile,
  });

  const bearer = requireBearerAuth({
    verifier: { verifyAccessToken: (token) => provider.verifyAccessToken(token) },
    resourceMetadataUrl: `${publicUrl}/.well-known/oauth-protected-resource`,
  });

  /**
   * The registry this caller gets.
   *
   * Single-tenant: the container's own, as upstream does it. Multi-tenant: one
   * built from the caller's own enrolment record, so two callers are never in
   * one registry and `instance: "all"` can never fan out across tenants.
   *
   * The SDK calls this factory once per HTTP request and names this exact use
   * — "multi-tenant servers keyed off authInfo". A single shared instance
   * would answer the second caller with the first caller's access.
   */
  async function registryFor(
    authInfo: { extra?: unknown } | undefined,
  ): Promise<InstanceRegistry | CoolifyConfig> {
    if (!config.tenancy) {
      const single = config.instances ?? config.coolify;
      if (!single) throw new Error('This server is not configured with a Coolify instance.');
      return single;
    }
    const subject = subjectFromAuthInfo(authInfo?.extra);
    if (!subject) {
      // A token with no subject cannot be resolved to a tenant, and guessing
      // which one it meant is exactly how two tenants cross. Refuse instead.
      throw new Error('This token is not bound to an account. Reconnect to sign in again.');
    }
    try {
      return await registryForCaller(config.tenancy.store, subject);
    } catch (error) {
      if (error instanceof NotEnrolledError) {
        throw new Error(
          `No Coolify instance is linked to this account yet. Link one at ${publicUrl}/enroll and then try again.`,
          { cause: error },
        );
      }
      throw error;
    }
  }

  const mcpHandler: McpHttpHandler = createMcpHandler(
    async (ctx) =>
      new CoolifyMcpServer(await registryFor(ctx.authInfo), {
        readonly: config.readonly,
        requireElicitation: true,
        // On by default here: a multi-client, internet-facing server is exactly
        // where "who did what" has to be answerable. COOLIFY_MCP_AUDIT=off opts out.
        auditByDefault: true,
      }),
    {
      onerror: (error) => console.error('mcp handler:', error.message),
    },
  );

  // 20 guesses a minute per IP on the credential-bearing endpoints.
  const authLimiter = new RateLimiter(20, 60_000);

  /**
   * Finish the OAuth request that was parked while the tenant logged in and,
   * if needed, enrolled.
   *
   * The request is re-validated rather than trusted: it has been through the
   * browser twice. The signature proves it came back unmodified, and this
   * proves it is still a request this server would have accepted — a client
   * may have been forgotten, or its metadata document re-fetched, in between.
   */
  async function completeFlow(query: string, identity: VerifiedIdentity): Promise<Response> {
    const params = new URLSearchParams(query);
    try {
      await provider.resolveClient(params.get('client_id') ?? '');
      const validated = provider.validateAuthorizationRequest(params);
      const { redirectTo } = provider.completeAuthorization(validated, {
        provider: identity.provider,
        sub: identity.sub,
      });
      return redirect(redirectTo);
    } catch (error) {
      if (error instanceof OAuthErrorResponse) {
        return html(`<p>Authorization request rejected: ${escapeHtml(error.description)}</p>`, 400);
      }
      throw error;
    }
  }

  async function handle(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/$/, '') || '/';
    const clientIp = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'local';

    if (path === '/healthz') {
      // Still "ok": the server is answering. But state that lives only in
      // memory (#417) is one restart from vanishing, and this is where the
      // thing doing the restarting looks.
      return json(
        provider.persistenceDegraded ? { status: 'ok', persistence: 'degraded' } : { status: 'ok' },
      );
    }

    // ── landing page and static assets ──────────────────────────────────
    // Browser requests to the root get the landing page. Non-browser
    // clients (MCP clients, curl without Accept: text/html) fall through
    // to the existing 401 challenge or 404.
    if (path === '/' && (request.method === 'GET' || request.method === 'HEAD')) {
      const accept = request.headers.get('accept') ?? '';
      if (accept.includes('text/html') || request.method === 'HEAD') {
        const page = await servePublicFile('index.html', 60, request.method);
        if (page) return page;
      }
    }

    // Static assets: CSS, JS, favicon, robots.txt.
    if (
      (request.method === 'GET' || request.method === 'HEAD') &&
      (path.startsWith('/assets/') || path === '/favicon.svg' || path === '/robots.txt')
    ) {
      const file = await servePublicFile(path, 300, request.method);
      if (file) return file;
    }

    // Public text pages: /privacy, /terms
    if (
      (path === '/privacy' || path === '/terms') &&
      (request.method === 'GET' || request.method === 'HEAD')
    ) {
      const file = await servePublicFile(`${path.slice(1)}.html`, 60, request.method);
      if (file) return file;
    }

    if (
      path === '/.well-known/oauth-protected-resource' ||
      path === '/.well-known/oauth-protected-resource/mcp'
    ) {
      return json(provider.protectedResourceMetadata());
    }
    // The path-suffix form is what a client derives from the resource URL's
    // /mcp path per RFC 8414 §3.1; both forms must answer.
    if (
      path === '/.well-known/oauth-authorization-server' ||
      path === '/.well-known/oauth-authorization-server/mcp'
    ) {
      return json(provider.authorizationServerMetadata());
    }

    if (path === '/register' && request.method === 'POST') {
      if (!authLimiter.allow(`reg:${clientIp}`)) {
        return json({ error: 'too_many_requests' }, 429);
      }
      try {
        const metadata = (await request.json()) as Record<string, unknown>;
        return json(provider.registerClient(metadata), 201);
      } catch (error) {
        if (error instanceof OAuthErrorResponse) return oauthError(error);
        return json({ error: 'invalid_client_metadata' }, 400);
      }
    }

    if (path === '/authorize' && request.method === 'GET') {
      const clientId = url.searchParams.get('client_id') ?? '';
      // A URL client_id makes this leg fetch from a host the requester chose
      // (#340), so it gets the same per-IP limit as the credential-bearing
      // legs. A registered id stays unlimited: that page is in-memory work.
      if (isClientIdUrl(clientId) && !authLimiter.allow(`cimd:${clientIp}`)) {
        return html('<p>Too many attempts. Try again in a minute.</p>', 429);
      }
      try {
        await provider.resolveClient(clientId);
        const validated = provider.validateAuthorizationRequest(url.searchParams);
        if (config.tenancy) {
          // Validated before we leave: a malformed redirect_uri must be
          // rejected here, not after a round trip through the provider.
          const state = sealLoginState(url.searchParams.toString());
          const providers = configuredProviders(config.tenancy.identity);
          if (providers.length === 1) {
            return redirect(loginRedirectUrl(config.tenancy.identity, providers[0], state));
          }
          return html(loginChooserPage(config.tenancy.identity, providers, state));
        }
        return html(
          authorizePage(url.searchParams, validated.client.client_name ?? 'An MCP client'),
        );
      } catch (error) {
        if (error instanceof OAuthErrorResponse) {
          // Client/redirect problems must not redirect (open-redirect guard);
          // render them instead.
          return html(
            `<p>Authorization request rejected: ${escapeHtml(error.description)}</p>`,
            400,
          );
        }
        throw error;
      }
    }

    if (path === '/authorize' && request.method === 'POST') {
      if (!authLimiter.allow(`auth:${clientIp}`)) {
        return html('<p>Too many attempts. Try again in a minute.</p>', 429);
      }
      const form = new URLSearchParams(await request.text());
      let validated;
      try {
        await provider.resolveClient(form.get('client_id') ?? '');
        validated = provider.validateAuthorizationRequest(form);
      } catch (error) {
        if (error instanceof OAuthErrorResponse) {
          return html(
            `<p>Authorization request rejected: ${escapeHtml(error.description)}</p>`,
            400,
          );
        }
        throw error;
      }

      if (!config.coolify) {
        // Unreachable in multi mode — the GET leg redirects to the identity
        // provider — but a POST straight to this path must not fall through to
        // a proof check with nothing to prove against.
        return html('<p>This server does not use token proof of access.</p>', 404);
      }
      const presented = form.get('coolify_token') ?? '';
      const proof = presented
        ? await validateCoolifyToken(
            config.coolify.baseUrl,
            presented,
            config.coolify.customHeaders,
          )
        : ({ ok: false } as const);
      // `presented` is not referenced past this line: used once as proof,
      // then gone. That property is the tier-2 design.
      if (!proof.ok) {
        form.delete('coolify_token');
        return html(
          authorizePage(
            form,
            validated.client.client_name ?? 'An MCP client',
            'That token was not accepted by your Coolify instance. Check it and try again.',
          ),
          401,
        );
      }

      const { redirectTo } = provider.completeAuthorization(validated);
      return new Response(null, {
        status: 302,
        headers: { location: redirectTo, 'cache-control': 'no-store' },
      });
    }

    // =========================================================================
    // Multi-tenant: identity callback and enrolment
    //
    // No cookies and no sessions, matching the upstream authorize form: every
    // page carries its whole state in a signed ticket. Nothing here is served
    // at all in single-tenant mode.
    // =========================================================================

    const callbackProvider: Provider | undefined =
      path === '/auth/github/callback'
        ? 'github'
        : path === '/auth/google/callback'
          ? 'google'
          : undefined;
    if (config.tenancy && callbackProvider && request.method === 'GET') {
      if (!authLimiter.allow(`cb:${clientIp}`)) {
        return html('<p>Too many attempts. Try again in a minute.</p>', 429);
      }
      let query: string;
      try {
        query = openLoginState(url.searchParams.get('state') ?? '').query;
      } catch (error) {
        return html(
          `<p>${escapeHtml(error instanceof IdentityError ? error.message : 'The login could not be verified.')}</p>`,
          400,
        );
      }

      let identity;
      try {
        identity = await exchangeCodeForIdentity(
          config.tenancy.identity,
          callbackProvider,
          url.searchParams.get('code') ?? '',
        );
      } catch (error) {
        return html(
          `<p>${escapeHtml(error instanceof IdentityError ? error.message : 'The login failed.')}</p>`,
          400,
        );
      }

      const record = await config.tenancy.store.read(identity);
      const enrolled = (record?.instances.length ?? 0) > 0;

      // Arriving without an OAuth request in hand — someone opened /enroll
      // directly to manage or revoke what they linked. There is nothing to
      // complete, so show the page.
      if (query === '') {
        return html(
          enrollPage({
            login: identity.login,
            record,
            egressAddresses: config.tenancy.egressAddresses,
            continueState: sealEnrolmentTicket(identity, ''),
          }),
        );
      }

      if (!enrolled) {
        return html(
          enrollPage({
            login: identity.login,
            record,
            egressAddresses: config.tenancy.egressAddresses,
            continueState: sealEnrolmentTicket(identity, query),
            notice: 'Signed in. Link a Coolify instance to finish connecting.',
          }),
        );
      }

      return completeFlow(query, identity);
    }

    if (config.tenancy && path === '/enroll' && request.method === 'GET') {
      // No identity yet, so this is a login with nothing to complete
      // afterwards; the callback recognises the empty request and shows the
      // management page.
      const state = sealLoginState('');
      const providers = configuredProviders(config.tenancy.identity);
      if (providers.length === 1) {
        return redirect(loginRedirectUrl(config.tenancy.identity, providers[0], state));
      }
      return html(loginChooserPage(config.tenancy.identity, providers, state));
    }

    if (config.tenancy && path === '/enroll' && request.method === 'POST') {
      if (!authLimiter.allow(`enroll:${clientIp}`)) {
        return html('<p>Too many attempts. Try again in a minute.</p>', 429);
      }
      const form = new URLSearchParams(await request.text());
      let ticket;
      try {
        ticket = openEnrolmentTicket(form.get('continue') ?? '');
      } catch (error) {
        return html(
          `<p>${escapeHtml(error instanceof IdentityError ? error.message : 'The enrolment session expired.')}</p>`,
          400,
        );
      }
      const { identity, query } = ticket;
      const existing = await config.tenancy.store.read(identity);

      const page = (error?: string, notice?: string, record?: TenantRecord): Response =>
        html(
          enrollPage({
            login: identity.login,
            record: record ?? existing,
            error,
            notice,
            egressAddresses: config.tenancy?.egressAddresses,
            continueState: sealEnrolmentTicket(identity, query),
          }),
          error ? 400 : 200,
        );

      const name = (form.get('name') ?? '').trim().toLowerCase();
      if (!isValidInstanceName(name)) {
        return page('Use lowercase letters, digits and hyphens for the name.');
      }

      const token = form.get('token') ?? '';
      const probe = await (config.tenancy.probe ?? probeCoolify)(form.get('base_url') ?? '', token);
      if (!probe.ok) return page(probe.reason);

      // Re-parse rather than trusting the submitted spelling: what gets stored
      // is the canonical origin the probe actually reached.
      const baseUrl = normalizeBaseUrl(new URL(form.get('base_url') ?? ''));
      const instances = (existing?.instances ?? []).filter((entry) => entry.name !== name);
      instances.push({ name, baseUrl, accessToken: token });
      const record: TenantRecord = {
        instances,
        updatedAt: Date.now(),
        login: identity.login,
      };
      await config.tenancy.store.write(identity, record);

      if (query === '') {
        return page(undefined, `Linked ${name} (${probe.teamName}).`, record);
      }
      return completeFlow(query, identity);
    }

    if (config.tenancy && path === '/enroll/revoke' && request.method === 'POST') {
      if (!authLimiter.allow(`enroll:${clientIp}`)) {
        return html('<p>Too many attempts. Try again in a minute.</p>', 429);
      }
      let ticket;
      try {
        ticket = openEnrolmentTicket(
          new URLSearchParams(await request.text()).get('continue') ?? '',
        );
      } catch (error) {
        return html(
          `<p>${escapeHtml(error instanceof IdentityError ? error.message : 'The enrolment session expired.')}</p>`,
          400,
        );
      }
      await config.tenancy.store.revoke(ticket.identity);
      return html(
        enrollPage({
          login: ticket.identity.login,
          egressAddresses: config.tenancy.egressAddresses,
          continueState: sealEnrolmentTicket(ticket.identity, ticket.query),
          notice:
            'Unlinked. The stored tokens were destroyed, not merely marked deleted. Any MCP ' +
            'client connected to this account will stop working immediately.',
        }),
      );
    }

    if (path === '/token' && request.method === 'POST') {
      if (!authLimiter.allow(`token:${clientIp}`)) {
        return json({ error: 'too_many_requests' }, 429);
      }
      try {
        const body = new URLSearchParams(await request.text());
        await provider.resolveClient(body.get('client_id') ?? '');
        return json(provider.exchange(body));
      } catch (error) {
        if (error instanceof OAuthErrorResponse) return oauthError(error);
        throw error;
      }
    }

    if (path === '/mcp') {
      const authResult = await bearer(request);
      if (authResult instanceof Response) return authResult;

      // The audit line is written by the server, not here (#370). Peeking at
      // the request body could only ever say what was ASKED; the line that
      // matters says what happened, which is only known once the tool has run.
      // `authInfo` carries the OAuth client id through to it.
      return mcpHandler.fetch(request, { authInfo: authResult });
    }

    return json({ error: 'not_found' }, 404);
  }

  return { fetch: handle, provider };
}
