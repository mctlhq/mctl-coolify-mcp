#!/usr/bin/env node

/**
 * HTTP mode entry point (#303): Streamable HTTP transport + OAuth 2.1,
 * deployable as a container next to the Coolify instance it manages.
 *
 * stdio (`index.ts`) remains the default and is untouched — this is an
 * additive second transport over the same 45 tools.
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import {
  createHttpApp,
  describeListen,
  listenOptionsFromEnv,
  normalizePublicUrl,
} from './lib/http-server.js';
import {
  checkStartupConfig,
  DEFAULT_OAUTH_STATE_FILE,
  ensureStateFileWritable,
} from './lib/startup-check.js';
import { registryFromEnv, type InstanceRegistry } from './lib/instances.js';
import { identityFromEnv } from './lib/identity.js';
import { VaultClient, vaultFromEnv } from './lib/vault.js';
import { StateFileVaultSync, hydrateStateFile } from './lib/oauth-state-vault.js';
import { VaultTenantStore } from './lib/tenancy.js';
import type { TenancyConfig } from './lib/http-server.js';
import type { CoolifyConfig } from './types/coolify.js';

/**
 * Cap on buffered request bodies. The largest legitimate request this server
 * sees is a tools/call with a compose file in it — comfortably under 1MB —
 * so 5MB is generous headroom while keeping "stream garbage forever" from
 * being a free memory exhaustion.
 */
const MAX_BODY_BYTES = 5 * 1024 * 1024;

/**
 * Multi-tenant mode's default OAuth state path — the container's own
 * writable layer, not a mounted volume. hydrateStateFile/StateFileVaultSync
 * (oauth-state-vault.ts) are what make a file here survive a restart.
 */
const DEFAULT_MULTI_TENANT_STATE_FILE = '/tmp/coolify-mcp-oauth-state.json';

class BodyTooLarge extends Error {}

/**
 * Minimal Node → web-standard adapter. The app is fetch-shaped
 * (Request in, Response out); this is the only Node-specific code.
 */
async function toRequest(req: IncomingMessage, base: string): Promise<Request> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    total += (chunk as Buffer).length;
    if (total > MAX_BODY_BYTES) throw new BodyTooLarge();
    chunks.push(chunk as Buffer);
  }
  const body = Buffer.concat(chunks);
  return new Request(`${base}${req.url ?? '/'}`, {
    method: req.method,
    headers: Object.entries(req.headers).flatMap(([key, value]) =>
      value === undefined
        ? []
        : Array.isArray(value)
          ? value.map((v) => [key, v] as [string, string])
          : [[key, value] as [string, string]],
    ),
    body: body.length > 0 ? body : undefined,
  });
}

async function writeResponse(response: Response, res: ServerResponse): Promise<void> {
  res.writeHead(response.status, Object.fromEntries(response.headers.entries()));
  if (response.body) {
    // Stream rather than buffer: SSE-upgraded MCP responses stay live.
    const reader = response.body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      res.write(value);
    }
  }
  res.end();
}

async function main(): Promise<void> {
  // Collect every configuration problem before failing, so the person staring
  // at Coolify's deploy log fixes the lot in one pass instead of one per boot.
  const problems: string[] = [];
  const baseUrl = process.env.COOLIFY_BASE_URL || '';
  const accessToken = process.env.COOLIFY_ACCESS_TOKEN || '';
  const rawPublicUrl = process.env.MCP_PUBLIC_URL || '';

  // Multi-tenant mode (MCP_TENANCY=multi): every caller brings their own
  // Coolify, so the operator needs none and the container holds no Coolify
  // credential of its own at all.
  const multiTenant = (process.env.MCP_TENANCY || 'single').toLowerCase() === 'multi';

  if (!multiTenant && !baseUrl) {
    problems.push(
      'COOLIFY_BASE_URL is not set. Set it to your Coolify URL, e.g. https://coolify.example.com',
    );
  }
  if (!multiTenant && !accessToken) {
    problems.push(
      'COOLIFY_ACCESS_TOKEN is not set. Create one in Coolify under Keys & Tokens → API tokens',
    );
  }

  let publicUrl = '';
  if (!rawPublicUrl) {
    problems.push(
      'MCP_PUBLIC_URL is not set. Set it to the public URL of this container, e.g. https://mcp.example.com (on Coolify, ${SERVICE_FQDN_COOLIFYMCP} provides it)',
    );
  } else {
    try {
      publicUrl = normalizePublicUrl(rawPublicUrl);
      if (publicUrl.startsWith('http://') && process.env.MCP_ALLOW_INSECURE_HTTP !== 'true') {
        // OAuth over plaintext hands bearer tokens to the network. Refuse
        // unless someone says, explicitly and greppably, that they are
        // developing locally.
        problems.push(
          `MCP_PUBLIC_URL is ${publicUrl} — it must be https. For local development only, set MCP_ALLOW_INSECURE_HTTP=true`,
        );
      }
    } catch {
      problems.push(`MCP_PUBLIC_URL is not a usable URL: "${rawPublicUrl}"`);
    }
  }

  // Startup self-check (#368): shape problems (unexpanded ${VAR} literals,
  // pasted whitespace, a doubled /api/v1, a half-set CF Access pair) that
  // would otherwise surface as unexplained 401s deep inside tool calls.
  const check = checkStartupConfig(process.env, 'http');
  problems.push(...check.errors);

  // The OAuth state file (#417). Its default is right in the image and wrong
  // everywhere else, and the write that finds out runs on a timer after the
  // first registration has already answered 201. Ask now instead.
  //
  // Multi-tenant mode defaults it under /tmp instead: /data is a volume this
  // mode does not mount (see oauth-state-vault.ts — Vault is the durable
  // store, and /tmp is scratch space this container already has for free).
  // An operator who sets MCP_OAUTH_STATE_FILE explicitly is still honored
  // either way, e.g. a self-hosted operator running multi mode with their
  // own volume.
  const stateFile =
    process.env.MCP_OAUTH_STATE_FILE ||
    (multiTenant ? DEFAULT_MULTI_TENANT_STATE_FILE : DEFAULT_OAUTH_STATE_FILE);
  const stateProblem = ensureStateFileWritable(
    stateFile,
    Boolean(process.env.MCP_OAUTH_STATE_FILE),
  );
  if (stateProblem) problems.push(stateProblem);

  // Warnings print even when startup then fails: the operator staring at the
  // deploy log should learn everything in one boot, not one problem per boot.
  for (const warning of check.warnings) console.error(`coolify-mcp: warning: ${warning}`);
  if (problems.length > 0) {
    console.error('coolify-mcp http mode cannot start:');
    for (const problem of problems) console.error(`  - ${problem}`);
    process.exit(1);
  }

  // The instance registry (#367). The default instance carries the CF Access
  // service token (#373) on every Coolify API request, including the tier-2
  // proof-of-access fetch — never on any other fetch this server makes.
  // Proof of access validates against the default instance ONLY: a fleet is
  // one trust domain, so proving membership of the default proves the fleet.
  let registry: InstanceRegistry | undefined;
  let coolify: CoolifyConfig | undefined;
  if (!multiTenant) {
    try {
      registry = registryFromEnv(process.env);
    } catch (error) {
      console.error('coolify-mcp http mode cannot start:');
      console.error(`  - ${error instanceof Error ? error.message : String(error)}`);
      process.exit(1);
    }
    coolify = registry.default;
  }

  // Multi-tenant needs an identity provider and somewhere to keep each
  // tenant's credential. Both are checked here rather than on first use: a
  // server that boots without them would 500 the first person to try to
  // connect, long after the deploy log has scrolled past.
  let tenancy: TenancyConfig | undefined;
  let stateVault: VaultClient | undefined;
  if (multiTenant) {
    const identity = identityFromEnv(process.env, publicUrl);
    const vaultConfig = vaultFromEnv(process.env);
    if (!identity) {
      problems.push(
        'MCP_TENANCY=multi needs at least one identity provider: GITHUB_CLIENT_ID + ' +
          'GITHUB_CLIENT_SECRET (callback: ' +
          `${publicUrl || 'https://your-domain'}/auth/github/callback), and/or GOOGLE_CLIENT_ID ` +
          `+ GOOGLE_CLIENT_SECRET (callback: ${publicUrl || 'https://your-domain'}/auth/google/callback)`,
      );
    }
    if (!vaultConfig) {
      problems.push(
        'MCP_TENANCY=multi needs VAULT_ADDR and VAULT_KV_MOUNT (a KV v2 mount with max_versions=1)',
      );
    }
    if (identity && vaultConfig) {
      // One client, shared between the tenant store and the OAuth state
      // mirror: both are the same Vault mount, and sharing means one
      // Kubernetes-auth login and one lease renewal, not two.
      const vault = new VaultClient(vaultConfig);
      tenancy = {
        store: new VaultTenantStore(vault),
        identity,
        egressAddresses: (process.env.MCP_EGRESS_ADDRESSES || '')
          .split(',')
          .map((address) => address.trim())
          .filter(Boolean),
      };
      stateVault = vault;
    }
    if (problems.length > 0) {
      console.error('coolify-mcp http mode cannot start:');
      for (const problem of problems) console.error(`  - ${problem}`);
      process.exit(1);
    }
  }
  // Restore whatever OAuth state survived the last restart before
  // OAuthProvider's constructor reads the (otherwise empty, freshly-created)
  // file — hydrateStateFile is a no-op on first boot, when Vault has nothing
  // yet, exactly like the file-based load() it stands in front of.
  if (stateVault) await hydrateStateFile(stateVault, stateFile);

  const listen = listenOptionsFromEnv(process.env);
  const readonly = process.env.MCP_READONLY === 'true';

  const app = createHttpApp({
    coolify,
    instances: registry,
    publicUrl,
    accessTokenTtl: Number(process.env.MCP_ACCESS_TOKEN_TTL || 3600),
    // Short by design: "removed from Coolify" should mean "loses MCP access"
    // within hours, because tier-2 re-checks proof of access at re-authorize.
    refreshTokenTtl: Number(process.env.MCP_REFRESH_TOKEN_TTL || 28_800),
    stateFile,
    readonly,
    tenancy,
  });

  const server = createServer((req, res) => {
    toRequest(req, publicUrl)
      .then((request) => app.fetch(request))
      .then((response) => writeResponse(response, res))
      .catch((error: unknown) => {
        if (error instanceof BodyTooLarge) {
          res.writeHead(413, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: 'payload_too_large' }));
          req.destroy();
          return;
        }
        console.error('http:', error instanceof Error ? error.message : String(error));
        if (!res.headersSent) {
          res.writeHead(500, { 'content-type': 'application/json' });
        }
        res.end(JSON.stringify({ error: 'internal_error' }));
      });
  });

  // Receive-side timeouts. These bound reading the request (headers + body),
  // not writing the response, so long-lived SSE streams are unaffected.
  server.headersTimeout = 15_000;
  server.requestTimeout = 30_000;

  const stateSync = stateVault ? new StateFileVaultSync(stateVault, stateFile) : undefined;
  stateSync?.start();

  server.listen(listen, () => {
    console.error(
      `coolify-mcp http mode on ${describeListen(listen)} (public: ${publicUrl}${readonly ? ', read-only' : ''})`,
    );
  });

  const shutdown = (): void => {
    app.provider.flush();
    // Best-effort: the 3s force-exit below already bounds how long this can
    // delay a shutdown, and a sync that loses this race loses only the very
    // last write, the same trade writeState() itself already makes.
    void stateSync?.flush().finally(() => stateSync.stop());
    server.close(() => process.exit(0));
    // Belt and braces: if a live SSE stream keeps close() waiting, leave anyway.
    setTimeout(() => process.exit(0), 3000).unref();
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

main().catch((error: unknown) => {
  console.error('coolify-mcp http mode: fatal error during startup:', error);
  process.exit(1);
});
