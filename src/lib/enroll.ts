/**
 * Enrolment: a tenant links their own Coolify to their account.
 *
 * ## Why this is a web page and not an MCP tool
 *
 * A tool argument travels through the model's context and the conversation
 * transcript. A Coolify API token is a write-capable credential for someone's
 * production estate, and the one place it must never be written is a chat log
 * that gets stored, replayed and summarised. So enrolment is an ordinary HTML
 * form on the server's own origin, posted straight to the process that stores
 * it, and the MCP surface only ever hands out a link to it.
 *
 * ## Why the URL is treated as hostile
 *
 * The base URL is supplied by a stranger and this server runs inside a
 * cluster. Fetching it naively is a server-side request forgery primitive
 * aimed at the cluster's own network — the Kubernetes API, Vault, link-local
 * metadata. Every probe therefore goes through the same three checks the
 * upstream SSRF guard applies to client metadata documents: the URL as
 * written, every address it resolves to, and a pinned lookup so the connection
 * cannot be rebound to a different address after the check passed.
 *
 * Upstream's own `validateCoolifyToken` uses a bare fetch, which is correct
 * there — its base URL comes from the operator's environment — and would be a
 * hole here.
 */
import { request as httpsRequest } from 'node:https';
import { isIP } from 'node:net';
import {
  UnsafeUrlError,
  assertPublicUrl,
  pinnedLookup,
  resolvePublicAddresses,
  type Resolver,
} from './ssrf.js';
import type { TenantRecord } from './tenancy.js';

const PROBE_TIMEOUT_MS = 10_000;
const PROBE_MAX_BYTES = 64 * 1024;

/** Coolify instance names a tenant may choose. Kept to what is safe in a path and a tool argument. */
const NAME_PATTERN = /^[a-z0-9][a-z0-9-]{0,30}$/;

export type ProbeResult = { ok: true; teamName: string } | { ok: false; reason: string };

/**
 * Ask a candidate Coolify whether this token is good for it.
 *
 * `GET /api/v1/teams/current` 401s on a bad token and names the team on a good
 * one. The token is used for this one request and then belongs to the caller
 * to store or discard; nothing is retained here.
 *
 * `/teams/current` rather than the spec's `/team`: the old path is still
 * routed upstream and is the only one that exists on Coolify 4.0–4.2.
 */
export async function probeCoolify(
  rawBaseUrl: string,
  token: string,
  options: { resolver?: Resolver } = {},
): Promise<ProbeResult> {
  let url: URL;
  try {
    // https only. A tenant's token crossing the public internet in clear is
    // not a trade we make on their behalf, and a plaintext Coolify is almost
    // always one on a private address, which the next check refuses anyway.
    url = assertPublicUrl(rawBaseUrl);
  } catch (error) {
    return {
      ok: false,
      reason:
        error instanceof UnsafeUrlError
          ? `That address cannot be reached from here: ${error.message}. It must be a public https URL.`
          : 'That address is not a usable URL.',
    };
  }

  const host = url.hostname.replace(/^\[|\]$/g, '');
  const literal = isIP(host);
  let addresses;
  try {
    addresses =
      literal !== 0
        ? [{ address: host, family: literal === 6 ? (6 as const) : (4 as const) }]
        : await resolvePublicAddresses(host, options.resolver);
  } catch (error) {
    return {
      ok: false,
      reason:
        error instanceof UnsafeUrlError
          ? `That address cannot be reached from here: ${error.message}.`
          : 'That address could not be resolved.',
    };
  }

  const probeUrl = new URL(`${url.pathname.replace(/\/+$/, '')}/api/v1/teams/current`, url.origin);

  return new Promise<ProbeResult>((resolve) => {
    const req = httpsRequest(
      probeUrl,
      {
        method: 'GET',
        headers: {
          authorization: `Bearer ${token}`,
          accept: 'application/json',
          'user-agent': 'mctl-coolify-mcp',
        },
        lookup: pinnedLookup(addresses),
        timeout: PROBE_TIMEOUT_MS,
      },
      (res) => {
        // Redirects are not followed: a 3xx would re-open every question the
        // checks above just answered. A Coolify behind an SSO wall lands here,
        // which is the honest answer — we cannot reach its API.
        if (res.statusCode === 401 || res.statusCode === 403) {
          res.resume();
          resolve({
            ok: false,
            reason:
              'Your Coolify did not accept that token. Check it, and check that API access is ' +
              'enabled under Settings → Advanced.',
          });
          return;
        }
        if (res.statusCode !== 200) {
          res.resume();
          resolve({
            ok: false,
            reason: `Your Coolify answered ${res.statusCode ?? 'nothing'} at /api/v1/teams/current. Redirects are not followed.`,
          });
          return;
        }
        const chunks: Buffer[] = [];
        let size = 0;
        res.on('data', (chunk: Buffer) => {
          size += chunk.length;
          if (size > PROBE_MAX_BYTES) {
            req.destroy();
            resolve({ ok: false, reason: 'Your Coolify returned an implausibly large response.' });
            return;
          }
          chunks.push(chunk);
        });
        res.on('end', () => {
          try {
            const team = JSON.parse(Buffer.concat(chunks).toString('utf8')) as { name?: unknown };
            resolve({
              ok: true,
              teamName: typeof team.name === 'string' ? team.name : 'your team',
            });
          } catch {
            resolve({ ok: false, reason: 'Your Coolify did not return JSON at that address.' });
          }
        });
        res.on('error', () =>
          resolve({ ok: false, reason: 'The connection failed mid-response.' }),
        );
      },
    );
    req.on('timeout', () => {
      req.destroy();
      resolve({ ok: false, reason: 'Your Coolify did not answer within 10 seconds.' });
    });
    req.on('error', () =>
      resolve({
        ok: false,
        reason:
          'Could not connect. If your Coolify is on a private network or behind a VPN, a hosted server cannot reach it.',
      }),
    );
    req.end();
  });
}

export function isValidInstanceName(name: string): boolean {
  return NAME_PATTERN.test(name);
}

/** Normalize a base URL for storage: no trailing slash, no query, no fragment. */
export function normalizeBaseUrl(url: URL): string {
  return `${url.origin}${url.pathname.replace(/\/+$/, '')}`;
}

export interface EnrollPageOptions {
  login: string;
  record?: TenantRecord;
  error?: string;
  notice?: string;
  /**
   * The addresses this server makes outbound calls from, shown only to a
   * logged-in tenant who may need them for Coolify's "Allowed API IPs".
   * Deliberately not in public documentation: publishing them would hand the
   * origin behind the CDN to anyone scanning.
   */
  egressAddresses?: string[];
  /** Present when the tenant arrived mid-login; posting continues that flow. */
  continueState?: string;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

export function enrollPage(options: EnrollPageOptions): string {
  const instances = options.record?.instances ?? [];
  const rows = instances
    .map(
      (instance) => `<tr>
        <td><code>${escapeHtml(instance.name)}</code></td>
        <td><code>${escapeHtml(instance.baseUrl)}</code></td>
      </tr>`,
    )
    .join('\n      ');

  const egress = options.egressAddresses?.length
    ? `<p class="note">If your Coolify restricts API access by IP (Settings &rarr; Advanced &rarr;
       Allowed API IPs), add ${options.egressAddresses.map((a) => `<code>${escapeHtml(a)}</code>`).join(', ')}.
       Most instances leave that setting off and need nothing here.</p>`
    : '';

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Link your Coolify</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 34rem; margin: 8vh auto; padding: 0 1rem; color: #1a1a1a; }
    h1 { font-size: 1.25rem; }
    p { line-height: 1.55; color: #444; }
    label { display: block; font-weight: 600; margin: 1.1rem 0 0.3rem; }
    input { width: 100%; padding: 0.6rem; font-size: 1rem; border: 1px solid #bbb; border-radius: 6px; box-sizing: border-box; }
    button { margin-top: 1.2rem; width: 100%; padding: 0.7rem; font-size: 1rem; border: 0; border-radius: 6px; background: #6b16ed; color: #fff; cursor: pointer; }
    button.secondary { background: #fff; color: #8a1f1f; border: 1px solid #f5b5b5; }
    table { width: 100%; border-collapse: collapse; margin: 0.8rem 0; font-size: 0.9rem; }
    td, th { text-align: left; padding: 0.35rem 0.5rem; border-bottom: 1px solid #eee; }
    .error { background: #fde8e8; border: 1px solid #f5b5b5; border-radius: 6px; padding: 0.6rem 0.8rem; color: #8a1f1f; }
    .notice { background: #e8f5e9; border: 1px solid #b5dbb8; border-radius: 6px; padding: 0.6rem 0.8rem; color: #1f5a25; }
    .note { font-size: 0.85rem; color: #666; }
    code { font-size: 0.85em; }
  </style>
</head>
<body>
  <h1>Link your Coolify</h1>
  <p>Signed in as <strong>${escapeHtml(options.login)}</strong>.</p>
  ${options.error ? `<p class="error">${escapeHtml(options.error)}</p>` : ''}
  ${options.notice ? `<p class="notice">${escapeHtml(options.notice)}</p>` : ''}
  ${
    instances.length > 0
      ? `<h2 style="font-size:1rem">Linked now</h2>
  <table><tr><th>Name</th><th>Address</th></tr>
      ${rows}
  </table>
  <form method="post" action="/enroll/revoke">
    ${options.continueState ? `<input type="hidden" name="continue" value="${escapeHtml(options.continueState)}">` : ''}
    <button class="secondary" type="submit">Unlink everything and delete the stored tokens</button>
  </form>`
      : '<p>Nothing is linked to this account yet.</p>'
  }
  <h2 style="font-size:1rem">Add an instance</h2>
  <form method="post" action="/enroll">
    ${options.continueState ? `<input type="hidden" name="continue" value="${escapeHtml(options.continueState)}">` : ''}
    <label for="name">Name</label>
    <input id="name" name="name" value="default" pattern="[a-z0-9][a-z0-9-]{0,30}" required>
    <p class="note">Lowercase letters, digits and hyphens. You use this to say which instance a request means.</p>
    <label for="base_url">Coolify address</label>
    <input id="base_url" name="base_url" type="url" placeholder="https://coolify.example.com" required>
    <p class="note">Must be reachable from the public internet over https. An instance on a private
    network or behind a VPN cannot be reached by a hosted server — run this server yourself for those.</p>
    <label for="token">Coolify API token</label>
    <input id="token" name="token" type="password" autocomplete="off" required>
    <p class="note">Create it under Keys &amp; Tokens &rarr; API tokens. <strong>Give it the least it
    needs</strong> — <code>read</code> alone to inspect, <code>deploy</code> to deploy. Avoid
    <code>root</code>. The token is stored encrypted and used only to answer your own requests.</p>
    ${egress}
    <button type="submit">Link this instance</button>
  </form>
</body>
</html>`;
}
