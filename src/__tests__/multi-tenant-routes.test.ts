/**
 * End-to-end route coverage for multi-tenant mode (identity callback,
 * enrolment, revocation) driven the same way `oauth.test.ts`'s "HTTP app
 * routes" block drives the single-tenant server: raw fetch() against
 * createHttpApp's handler, no reference-client machinery, because what is
 * under test here is this codebase's own routes, not protocol interop.
 *
 * `tenancy.probe` stands in for a live Coolify — dependency injection in the
 * same shape as `resolver`/`now` elsewhere, not a mocking framework; see its
 * doc comment on TenancyConfig. Everything else — ticket signing/verification,
 * the identity exchange, the store, the redirect back into the OAuth code
 * flow — runs for real.
 */
import { jest } from '@jest/globals';
import { createHash, randomBytes } from 'node:crypto';
import { createHttpApp, type HttpServerConfig } from '../lib/http-server.js';
import { MemoryTenantStore } from '../lib/tenancy.js';
import type { IdentityConfig } from '../lib/identity.js';
import type { ProbeResult } from '../lib/enroll.js';

const ISSUER = 'https://mcp.example.com';
const CALLBACK = 'https://client.example.com/callback';

const identity: IdentityConfig = {
  github: {
    clientId: 'gh-client-id',
    clientSecret: 'gh-client-secret',
    callbackUrl: `${ISSUER}/auth/github/callback`,
  },
};

const bothProvidersIdentity: IdentityConfig = {
  ...identity,
  google: {
    clientId: 'g-client-id',
    clientSecret: 'g-client-secret',
    callbackUrl: `${ISSUER}/auth/google/callback`,
  },
};

function pkcePair(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString('base64url');
  return { verifier, challenge: createHash('sha256').update(verifier).digest('base64url') };
}

/** Stands in for GitHub's two-leg exchange, keyed by the fake `code` presented. */
function mockGithub(users: Record<string, { id: number; login: string }>): void {
  global.fetch = jest.fn(async (input: unknown, init?: unknown) => {
    const url = String(input);
    if (url.startsWith('https://github.com/login/oauth/access_token')) {
      const body = new URLSearchParams((init as { body?: string })?.body ?? '');
      const code = body.get('code') ?? '';
      if (!(code in users)) {
        return new Response(JSON.stringify({ error: 'bad_verification_code' }));
      }
      return new Response(JSON.stringify({ access_token: `gho_${code}` }));
    }
    if (url === 'https://api.github.com/user') {
      const auth = (init as { headers?: Record<string, string> })?.headers?.authorization ?? '';
      const code = auth.replace('Bearer gho_', '');
      const user = users[code];
      return new Response(JSON.stringify(user ? { id: user.id, login: user.login } : {}), {
        status: user ? 200 : 404,
      });
    }
    throw new Error(`unexpected fetch in test: ${url}`);
  }) as typeof fetch;
}

/** Stands in for Google's two-leg OIDC exchange, keyed by the fake `code` presented. */
function mockGoogle(users: Record<string, { sub: string; email: string }>): void {
  global.fetch = jest.fn(async (input: unknown, init?: unknown) => {
    const url = String(input);
    if (url === 'https://oauth2.googleapis.com/token') {
      const body = new URLSearchParams((init as { body?: string })?.body ?? '');
      const code = body.get('code') ?? '';
      if (!(code in users)) {
        return new Response(JSON.stringify({ error: 'invalid_grant' }), { status: 400 });
      }
      return new Response(JSON.stringify({ access_token: `ya29_${code}` }));
    }
    if (url === 'https://openidconnect.googleapis.com/v1/userinfo') {
      const auth = (init as { headers?: Record<string, string> })?.headers?.authorization ?? '';
      const code = auth.replace('Bearer ya29_', '');
      const user = users[code];
      return new Response(JSON.stringify(user ?? {}), { status: user ? 200 : 404 });
    }
    throw new Error(`unexpected fetch in test: ${url}`);
  }) as typeof fetch;
}

function makeApp(
  overrides: {
    store?: MemoryTenantStore;
    probe?: (baseUrl: string, token: string) => Promise<ProbeResult>;
    identity?: IdentityConfig;
  } = {},
): { app: ReturnType<typeof createHttpApp>; store: MemoryTenantStore } {
  const store = overrides.store ?? new MemoryTenantStore();
  const app = createHttpApp({
    publicUrl: ISSUER,
    accessTokenTtl: 3600,
    refreshTokenTtl: 28_800,
    stateFile: '',
    readonly: false,
    tenancy: {
      store,
      identity: overrides.identity ?? identity,
      probe:
        overrides.probe ?? (async () => ({ ok: true, teamName: 'Acme' }) satisfies ProbeResult),
    },
  } satisfies HttpServerConfig);
  return { app, store };
}

async function registerClient(app: ReturnType<typeof createHttpApp>): Promise<string> {
  const response = await app.fetch(
    new Request(`${ISSUER}/register`, {
      method: 'POST',
      body: JSON.stringify({ redirect_uris: [CALLBACK], client_name: 'Test' }),
    }),
  );
  const body = (await response.json()) as { client_id: string };
  return body.client_id;
}

function extractHidden(html: string, name: string): string {
  const match = new RegExp(`name="${name}" value="([^"]*)"`).exec(html);
  if (!match) throw new Error(`no hidden field "${name}" in: ${html.slice(0, 200)}`);
  return match[1].replace(/&quot;/g, '"').replace(/&amp;/g, '&');
}

const realFetch = global.fetch;
afterEach(() => {
  global.fetch = realFetch;
  jest.restoreAllMocks();
});

describe('GET /authorize in multi-tenant mode', () => {
  it('redirects to the identity provider instead of asking for a Coolify token', async () => {
    const { app } = makeApp();
    const clientId = await registerClient(app);
    const { challenge } = pkcePair();
    const response = await app.fetch(
      new Request(
        `${ISSUER}/authorize?${new URLSearchParams({
          client_id: clientId,
          redirect_uri: CALLBACK,
          response_type: 'code',
          code_challenge: challenge,
          code_challenge_method: 'S256',
        })}`,
      ),
    );
    expect(response.status).toBe(302);
    const location = new URL(response.headers.get('location')!);
    expect(location.origin + location.pathname).toBe('https://github.com/login/oauth/authorize');
    expect(location.searchParams.get('scope')).toBe('');
    expect(location.searchParams.get('state')).toBeTruthy();
  });

  it('rejects a malformed request before ever redirecting to the identity provider', async () => {
    const { app } = makeApp();
    const response = await app.fetch(new Request(`${ISSUER}/authorize?client_id=unknown-client`));
    expect(response.status).toBe(400);
    expect(response.headers.get('location')).toBeNull();
  });

  it('shows a chooser instead of redirecting when more than one provider is configured', async () => {
    const { app } = makeApp({ identity: bothProvidersIdentity });
    const clientId = await registerClient(app);
    const { challenge } = pkcePair();
    const response = await app.fetch(
      new Request(
        `${ISSUER}/authorize?${new URLSearchParams({
          client_id: clientId,
          redirect_uri: CALLBACK,
          response_type: 'code',
          code_challenge: challenge,
          code_challenge_method: 'S256',
        })}`,
      ),
    );
    expect(response.status).toBe(200);
    const body = await response.text();
    expect(body).toContain('Continue with GitHub');
    expect(body).toContain('Continue with Google');
    const githubHref = /href="([^"]*)">Continue with GitHub/.exec(body)![1].replace(/&amp;/g, '&');
    const googleHref = /href="([^"]*)">Continue with Google/.exec(body)![1].replace(/&amp;/g, '&');
    expect(new URL(githubHref).origin + new URL(githubHref).pathname).toBe(
      'https://github.com/login/oauth/authorize',
    );
    expect(new URL(googleHref).origin + new URL(googleHref).pathname).toBe(
      'https://accounts.google.com/o/oauth2/v2/auth',
    );
    // Both links carry the same parked-request state, so completing either
    // finishes the same OAuth request.
    expect(new URL(githubHref).searchParams.get('state')).toBe(
      new URL(googleHref).searchParams.get('state'),
    );
  });
});

describe('Google as the identity provider', () => {
  it('signs in via /auth/google/callback and completes the parked OAuth request', async () => {
    mockGoogle({ 'the-code': { sub: '110169484474386276334', email: 'person@example.com' } });
    const { app, store } = makeApp({ identity: bothProvidersIdentity });
    const clientId = await registerClient(app);
    const { challenge } = pkcePair();

    const authorize = await app.fetch(
      new Request(
        `${ISSUER}/authorize?${new URLSearchParams({
          client_id: clientId,
          redirect_uri: CALLBACK,
          response_type: 'code',
          code_challenge: challenge,
          code_challenge_method: 'S256',
        })}`,
      ),
    );
    const chooserHtml = await authorize.text();
    const googleHref = /href="([^"]*)">Continue with Google/
      .exec(chooserHtml)![1]
      .replace(/&amp;/g, '&');
    const state = new URL(googleHref).searchParams.get('state')!;

    const callback = await app.fetch(
      new Request(
        `${ISSUER}/auth/google/callback?${new URLSearchParams({ code: 'the-code', state })}`,
      ),
    );
    expect(callback.status).toBe(200);
    const enrollHtml = await callback.text();
    expect(enrollHtml).toContain('person@example.com');
    const continueState = extractHidden(enrollHtml, 'continue');

    const enroll = await app.fetch(
      new Request(`${ISSUER}/enroll`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          continue: continueState,
          name: 'prod',
          base_url: 'https://coolify.example.com',
          token: 'tok',
        }).toString(),
      }),
    );
    expect(enroll.status).toBe(302);
    const location = new URL(enroll.headers.get('location')!);
    expect(location.origin + location.pathname).toBe(CALLBACK);
    expect(location.searchParams.get('code')).toBeTruthy();

    const record = await store.read({ provider: 'google', sub: '110169484474386276334' });
    expect(record?.instances[0]).toMatchObject({
      name: 'prod',
      baseUrl: 'https://coolify.example.com',
    });
  });
});

describe('the full enrolment journey', () => {
  it('signs in, shows the enrolment form, links an instance, and completes the parked OAuth request', async () => {
    mockGithub({ 'the-code': { id: 583231, login: 'octocat' } });
    const { app, store } = makeApp();
    const clientId = await registerClient(app);
    const { verifier, challenge } = pkcePair();

    const authorizeResponse = await app.fetch(
      new Request(
        `${ISSUER}/authorize?${new URLSearchParams({
          client_id: clientId,
          redirect_uri: CALLBACK,
          response_type: 'code',
          code_challenge: challenge,
          code_challenge_method: 'S256',
          state: 'client-state',
        })}`,
      ),
    );
    const loginState = new URL(authorizeResponse.headers.get('location')!).searchParams.get(
      'state',
    )!;

    // The identity callback: not enrolled yet, so it must show the form
    // rather than complete the flow.
    const callbackResponse = await app.fetch(
      new Request(
        `${ISSUER}/auth/github/callback?${new URLSearchParams({ code: 'the-code', state: loginState })}`,
      ),
    );
    expect(callbackResponse.status).toBe(200);
    const enrollHtml = await callbackResponse.text();
    expect(enrollHtml).toContain('Nothing is linked to this account yet');
    const ticket = extractHidden(enrollHtml, 'continue');

    // Link an instance; the probe is stubbed to accept it.
    const enrollResponse = await app.fetch(
      new Request(`${ISSUER}/enroll`, {
        method: 'POST',
        body: new URLSearchParams({
          continue: ticket,
          name: 'default',
          base_url: 'https://coolify.example.com',
          token: 'tenant-coolify-token',
        }),
      }),
    );

    // Enrolling completes the parked OAuth request: redirect back to the
    // client that originally asked for /authorize.
    expect(enrollResponse.status).toBe(302);
    const finalRedirect = new URL(enrollResponse.headers.get('location')!);
    expect(finalRedirect.origin + finalRedirect.pathname).toBe(CALLBACK);
    expect(finalRedirect.searchParams.get('state')).toBe('client-state');
    const code = finalRedirect.searchParams.get('code')!;
    expect(code).toBeTruthy();

    // The record actually landed in the store, keyed by the GitHub subject.
    const record = await store.read({ provider: 'github', sub: '583231' });
    expect(record?.instances).toEqual([
      {
        name: 'default',
        baseUrl: 'https://coolify.example.com',
        accessToken: 'tenant-coolify-token',
      },
    ]);

    // The code the OAuth flow issued exchanges normally, and the resulting
    // token is bound to the tenant who just enrolled — not to whoever asked.
    const tokenResponse = await app.fetch(
      new Request(`${ISSUER}/token`, {
        method: 'POST',
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          client_id: clientId,
          code,
          redirect_uri: CALLBACK,
          code_verifier: verifier,
        }),
      }),
    );
    expect(tokenResponse.status).toBe(200);
    const tokens = (await tokenResponse.json()) as { access_token: string };
    const verified = await app.provider.verifyAccessToken(tokens.access_token);
    expect(verified.extra).toEqual({ provider: 'github', sub: '583231' });
  });

  it('rejects a probe that fails, and keeps the tenant on the form', async () => {
    mockGithub({ c: { id: 1, login: 'a' } });
    const { app, store } = makeApp({
      probe: async () => ({ ok: false, reason: 'Your Coolify did not accept that token.' }),
    });

    const authorizeState = new URL(
      (await app.fetch(new Request(`${ISSUER}/enroll`))).headers.get('location')!,
    ).searchParams.get('state')!;
    const callbackHtml = await (
      await app.fetch(
        new Request(
          `${ISSUER}/auth/github/callback?${new URLSearchParams({ code: 'c', state: authorizeState })}`,
        ),
      )
    ).text();
    const ticket = extractHidden(callbackHtml, 'continue');

    const response = await app.fetch(
      new Request(`${ISSUER}/enroll`, {
        method: 'POST',
        body: new URLSearchParams({
          continue: ticket,
          name: 'default',
          base_url: 'https://coolify.example.com',
          token: 'bad-token',
        }),
      }),
    );
    expect(response.status).toBe(400);
    expect(await response.text()).toContain('did not accept that token');
    expect(await store.read({ provider: 'github', sub: '1' })).toBeUndefined();
  });

  it('refuses an instance name that is not lowercase letters, digits and hyphens', async () => {
    mockGithub({ c: { id: 2, login: 'b' } });
    const { app } = makeApp();
    const state = new URL(
      (await app.fetch(new Request(`${ISSUER}/enroll`))).headers.get('location')!,
    ).searchParams.get('state')!;
    const html = await (
      await app.fetch(
        new Request(`${ISSUER}/auth/github/callback?${new URLSearchParams({ code: 'c', state })}`),
      )
    ).text();
    const ticket = extractHidden(html, 'continue');

    const response = await app.fetch(
      new Request(`${ISSUER}/enroll`, {
        method: 'POST',
        body: new URLSearchParams({
          continue: ticket,
          name: 'Not Valid',
          base_url: 'https://coolify.example.com',
          token: 'tok',
        }),
      }),
    );
    expect(response.status).toBe(400);
    expect(await response.text()).toContain('lowercase letters');
  });
});

describe('management and revocation', () => {
  async function enrolledStore(): Promise<MemoryTenantStore> {
    const store = new MemoryTenantStore();
    await store.write(
      { provider: 'github', sub: '583231', login: 'octocat' },
      {
        instances: [
          { name: 'default', baseUrl: 'https://coolify.example.com', accessToken: 'tok' },
        ],
        updatedAt: Date.now(),
      },
    );
    return store;
  }

  it('lists linked instances and offers to unlink them', async () => {
    mockGithub({ c: { id: 583231, login: 'octocat' } });
    const { app } = makeApp({ store: await enrolledStore() });
    const state = new URL(
      (await app.fetch(new Request(`${ISSUER}/enroll`))).headers.get('location')!,
    ).searchParams.get('state')!;
    const html = await (
      await app.fetch(
        new Request(`${ISSUER}/auth/github/callback?${new URLSearchParams({ code: 'c', state })}`),
      )
    ).text();
    expect(html).toContain('coolify.example.com');
    expect(html).toContain('Unlink everything');
  });

  it('destroys the stored tokens on revoke, immediately', async () => {
    mockGithub({ c: { id: 583231, login: 'octocat' } });
    const store = await enrolledStore();
    const { app } = makeApp({ store });
    const state = new URL(
      (await app.fetch(new Request(`${ISSUER}/enroll`))).headers.get('location')!,
    ).searchParams.get('state')!;
    const html = await (
      await app.fetch(
        new Request(`${ISSUER}/auth/github/callback?${new URLSearchParams({ code: 'c', state })}`),
      )
    ).text();
    const ticket = extractHidden(html, 'continue');

    const revoked = await app.fetch(
      new Request(`${ISSUER}/enroll/revoke`, {
        method: 'POST',
        body: new URLSearchParams({ continue: ticket }),
      }),
    );
    expect(revoked.status).toBe(200);
    expect(await revoked.text()).toContain('destroyed, not merely marked deleted');
    expect(await store.read({ provider: 'github', sub: '583231' })).toBeUndefined();
  });
});

describe('the identity callback refuses forged or expired state', () => {
  it('refuses a state value that was not signed by this server', async () => {
    const { app } = makeApp();
    const response = await app.fetch(
      new Request(`${ISSUER}/auth/github/callback?code=x&state=forged.notasignature`),
    );
    expect(response.status).toBe(400);
  });

  it('never reaches the identity provider when the state fails first', async () => {
    const fetchSpy = jest.fn();
    global.fetch = fetchSpy as unknown as typeof fetch;
    const { app } = makeApp();
    await app.fetch(
      new Request(`${ISSUER}/auth/github/callback?code=x&state=forged.notasignature`),
    );
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

describe('single-tenant mode is unaffected', () => {
  it('serves none of the multi-tenant routes at all', async () => {
    const app = createHttpApp({
      coolify: { baseUrl: 'https://coolify.example.com', accessToken: 'env-token' },
      publicUrl: ISSUER,
      accessTokenTtl: 3600,
      refreshTokenTtl: 28_800,
      stateFile: '',
      readonly: false,
    });
    expect((await app.fetch(new Request(`${ISSUER}/enroll`))).status).toBe(404);
    expect(
      (await app.fetch(new Request(`${ISSUER}/auth/github/callback?code=x&state=y`))).status,
    ).toBe(404);
  });
});
