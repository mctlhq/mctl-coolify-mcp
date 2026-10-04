import { jest } from '@jest/globals';
import {
  IdentityError,
  clearOidcCache,
  configuredProviders,
  exchangeCodeForIdentity,
  identityFromEnv,
  loginRedirectUrl,
  openEnrolmentTicket,
  sealEnrolmentTicket,
  sealLoginState,
  type IdentityConfig,
} from '../lib/identity.js';
import { subjectFromAuthInfo, tenantKey } from '../lib/tenancy.js';
import { FakeOidcIssuer, ZITADEL_ISSUER } from './helpers/fake-oidc.js';

const PUBLIC_URL = 'https://coolify.mctl.ai';
const KEY = 'k'.repeat(48);

let issuer: FakeOidcIssuer;
let config: IdentityConfig;
const realFetch = global.fetch;

beforeEach(() => {
  process.env.MCP_REQUEST_STATE_KEY = KEY;
  clearOidcCache();
  issuer = new FakeOidcIssuer();
  global.fetch = jest.fn(issuer.fetch) as unknown as typeof fetch;
  config = {
    zitadel: {
      issuer: ZITADEL_ISSUER,
      clientId: issuer.clientId,
      clientSecret: issuer.clientSecret,
      callbackUrl: `${PUBLIC_URL}/auth/zitadel/callback`,
      displayName: 'ZITADEL',
    },
  };
});

afterEach(() => {
  delete process.env.MCP_REQUEST_STATE_KEY;
  global.fetch = realFetch;
  jest.restoreAllMocks();
});

/** Run one login: build the authorize URL, let the fake issuer approve it, exchange. */
async function login(
  approval: Parameters<FakeOidcIssuer['approve']>[2],
  options: { exchangeState?: string } = {},
): Promise<unknown> {
  const state = sealLoginState('client_id=abc');
  const authorizeUrl = await loginRedirectUrl(config, 'zitadel', state);
  issuer.approve('the-code', authorizeUrl, approval);
  return exchangeCodeForIdentity(config, 'zitadel', 'the-code', options.exchangeState ?? state);
}

describe('ZITADEL configuration', () => {
  const full = {
    ZITADEL_ISSUER: 'https://auth.mctl.ai/',
    ZITADEL_CLIENT_ID: ' zid ',
    ZITADEL_CLIENT_SECRET: ' zsecret ',
  };

  it('is off when none of its variables are set, leaving the others unchanged', () => {
    expect(identityFromEnv({}, PUBLIC_URL)).toBeUndefined();
    const resolved = identityFromEnv(
      { GITHUB_CLIENT_ID: 'a', GITHUB_CLIENT_SECRET: 'b' },
      PUBLIC_URL,
    );
    expect(resolved?.zitadel).toBeUndefined();
    expect(configuredProviders(resolved!)).toEqual(['github']);
  });

  it('is enough on its own, with the issuer normalised and the callback derived', () => {
    const resolved = identityFromEnv(full, PUBLIC_URL);
    expect(resolved?.zitadel).toEqual({
      issuer: 'https://auth.mctl.ai',
      clientId: 'zid',
      clientSecret: 'zsecret',
      callbackUrl: `${PUBLIC_URL}/auth/zitadel/callback`,
      displayName: 'ZITADEL',
    });
    expect(configuredProviders(resolved!)).toEqual(['zitadel']);
  });

  it('is offered after GitHub and Google, never instead of them', () => {
    const resolved = identityFromEnv(
      {
        ...full,
        GITHUB_CLIENT_ID: 'a',
        GITHUB_CLIENT_SECRET: 'b',
        GOOGLE_CLIENT_ID: 'c',
        GOOGLE_CLIENT_SECRET: 'd',
      },
      PUBLIC_URL,
    );
    expect(configuredProviders(resolved!)).toEqual(['github', 'google', 'zitadel']);
  });

  it('takes a display name for the chooser', () => {
    expect(
      identityFromEnv({ ...full, ZITADEL_DISPLAY_NAME: 'MCTL account' }, PUBLIC_URL)?.zitadel
        ?.displayName,
    ).toBe('MCTL account');
  });

  it('refuses a half-finished configuration instead of silently dropping the button', () => {
    expect(() =>
      identityFromEnv({ ZITADEL_CLIENT_ID: 'zid', ZITADEL_CLIENT_SECRET: 's' }, PUBLIC_URL),
    ).toThrow(/partly configured/);
    expect(() => identityFromEnv({ ZITADEL_ISSUER: 'https://auth.mctl.ai' }, PUBLIC_URL)).toThrow(
      /partly configured/,
    );
  });

  it('refuses an issuer that is not https', () => {
    expect(() =>
      identityFromEnv({ ...full, ZITADEL_ISSUER: 'http://auth.mctl.ai' }, PUBLIC_URL),
    ).toThrow(/must be an https URL/);
    expect(() => identityFromEnv({ ...full, ZITADEL_ISSUER: 'auth.mctl.ai' }, PUBLIC_URL)).toThrow(
      /must be an https URL/,
    );
  });
});

describe('ZITADEL login redirect', () => {
  it('uses the discovered endpoint, with PKCE S256, a nonce and minimal scopes', async () => {
    const state = sealLoginState('client_id=abc');
    const url = new URL(await loginRedirectUrl(config, 'zitadel', state));
    expect(url.origin + url.pathname).toBe(`${ZITADEL_ISSUER}/oauth/v2/authorize`);
    expect(url.searchParams.get('client_id')).toBe(issuer.clientId);
    expect(url.searchParams.get('redirect_uri')).toBe(`${PUBLIC_URL}/auth/zitadel/callback`);
    expect(url.searchParams.get('response_type')).toBe('code');
    expect(url.searchParams.get('scope')).toBe('openid email');
    expect(url.searchParams.get('state')).toBe(state);
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.get('code_challenge')).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(url.searchParams.get('nonce')).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('derives a different challenge and nonce for every login', async () => {
    const a = new URL(await loginRedirectUrl(config, 'zitadel', sealLoginState('q')));
    const b = new URL(await loginRedirectUrl(config, 'zitadel', sealLoginState('q')));
    expect(a.searchParams.get('code_challenge')).not.toBe(b.searchParams.get('code_challenge'));
    expect(a.searchParams.get('nonce')).not.toBe(b.searchParams.get('nonce'));
  });

  it('caches discovery instead of fetching it per login', async () => {
    await loginRedirectUrl(config, 'zitadel', 'a');
    await loginRedirectUrl(config, 'zitadel', 'b');
    expect(issuer.hits.discovery).toBe(1);
  });

  it('shares one discovery fetch between concurrent logins, and not a failed one', async () => {
    await Promise.all([
      loginRedirectUrl(config, 'zitadel', 'a'),
      loginRedirectUrl(config, 'zitadel', 'b'),
      loginRedirectUrl(config, 'zitadel', 'c'),
    ]);
    expect(issuer.hits.discovery).toBe(1);

    clearOidcCache();
    issuer.discoveryStatus = 500;
    const failed = await Promise.allSettled([
      loginRedirectUrl(config, 'zitadel', 'a'),
      loginRedirectUrl(config, 'zitadel', 'b'),
    ]);
    expect(failed.map((result) => result.status)).toEqual(['rejected', 'rejected']);
    expect(issuer.hits.discovery).toBe(2);
    issuer.discoveryStatus = 200;
    await expect(loginRedirectUrl(config, 'zitadel', 'a')).resolves.toContain(ZITADEL_ISSUER);
    expect(issuer.hits.discovery).toBe(3);
  });

  it('refuses a discovery document naming another issuer', async () => {
    issuer.discovery = { issuer: 'https://evil.example.com' };
    await expect(loginRedirectUrl(config, 'zitadel', 'a')).rejects.toThrow(
      /unusable configuration/,
    );
  });

  it('refuses endpoints off the issuer origin, or not https', async () => {
    issuer.discovery = { authorization_endpoint: 'https://evil.example.com/authorize' };
    await expect(loginRedirectUrl(config, 'zitadel', 'a')).rejects.toThrow(
      /unusable configuration/,
    );
    issuer.discovery = { token_endpoint: 'http://auth.example.com/oauth/v2/token' };
    await expect(loginRedirectUrl(config, 'zitadel', 'a')).rejects.toThrow(
      /unusable configuration/,
    );
  });

  it('does not cache a failed discovery', async () => {
    issuer.discovery = { issuer: 'https://evil.example.com' };
    await expect(loginRedirectUrl(config, 'zitadel', 'a')).rejects.toThrow(IdentityError);
    issuer.discovery = {};
    await expect(loginRedirectUrl(config, 'zitadel', 'a')).resolves.toContain(ZITADEL_ISSUER);
  });

  it('reports an unreachable issuer as such', async () => {
    global.fetch = jest
      .fn<() => Promise<never>>()
      .mockRejectedValue(new Error('ECONNREFUSED')) as unknown as typeof fetch;
    await expect(loginRedirectUrl(config, 'zitadel', 'a')).rejects.toThrow(/Could not reach/);
  });
});

describe('ZITADEL code exchange', () => {
  it('returns the ZITADEL sub as the subject and the email for display', async () => {
    await expect(
      login({ sub: '290000000000000001', email: 'person@example.com' }),
    ).resolves.toEqual({
      provider: 'zitadel',
      sub: '290000000000000001',
      login: 'person@example.com',
    });
  });

  it('authenticates with client_secret_basic and sends the PKCE verifier', async () => {
    await login({ sub: '1', email: 'a@example.com' });
    const [request] = issuer.tokenRequests;
    expect(request.authorization).toMatch(/^Basic /);
    expect(request.body.get('grant_type')).toBe('authorization_code');
    expect(request.body.get('redirect_uri')).toBe(`${PUBLIC_URL}/auth/zitadel/callback`);
    expect(request.body.get('code_verifier')).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(request.body.get('client_secret')).toBeNull();
  });

  it('form-encodes both halves of the Basic credentials (RFC 6749 §2.3.1)', async () => {
    // The fake issuer decodes them as ZITADEL does, so the login above only
    // succeeds with the encoding; this pins what went over the wire too.
    await login({ sub: '1', email: 'a@example.com' });
    const [request] = issuer.tokenRequests;
    const decoded = Buffer.from(request.authorization.replace(/^Basic /, ''), 'base64').toString();
    expect(issuer.clientId).toContain('@');
    expect(decoded).toBe(
      `${encodeURIComponent(issuer.clientId)}:${encodeURIComponent(issuer.clientSecret)}`,
    );
    expect(decoded).toContain('%40');
  });

  it('falls back to preferred_username, then sub, when there is no email', async () => {
    await expect(login({ sub: '7', claims: { preferred_username: 'zuser' } })).resolves.toEqual({
      provider: 'zitadel',
      sub: '7',
      login: 'zuser',
    });
    await expect(login({ sub: '8' })).resolves.toEqual({
      provider: 'zitadel',
      sub: '8',
      login: '8',
    });
  });

  it('does not carry any token out of the module', async () => {
    const identity = await login({ sub: '1', email: 'a@example.com' });
    expect(JSON.stringify(identity)).not.toContain('zitadel-access');
    expect(JSON.stringify(identity)).not.toContain('eyJ');
  });

  it('fails PKCE when the callback state is not the one the login started with', async () => {
    // The fake issuer checks the verifier against the challenge, as ZITADEL
    // does: a verifier derived from another state does not match.
    await expect(
      login({ sub: '1' }, { exchangeState: sealLoginState('client_id=abc') }),
    ).rejects.toThrow(/rejected the login/);
  });

  it('refuses to exchange without a state', async () => {
    await expect(exchangeCodeForIdentity(config, 'zitadel', 'the-code', '')).rejects.toThrow(
      /login state is missing/,
    );
    expect(issuer.hits.token).toBe(0);
  });

  it('refuses a token response without an ID token', async () => {
    const fetchMock = jest.fn(async (input: unknown, init?: RequestInit) => {
      if (String(input).endsWith('/oauth/v2/token')) return Response.json({ access_token: 'x' });
      return issuer.fetch(input, init);
    });
    global.fetch = fetchMock as unknown as typeof fetch;
    await expect(login({ sub: '1' })).rejects.toThrow(/did not issue a token/);
  });

  describe('ID token verification', () => {
    it('refuses a token from another issuer', async () => {
      await expect(
        login({ sub: '1', claims: { iss: 'https://evil.example.com' } }),
      ).rejects.toThrow(/unusable ID token/);
    });

    it('refuses a token for another client', async () => {
      await expect(
        login({ sub: '1', claims: { aud: 'someone-else', azp: undefined } }),
      ).rejects.toThrow(/unusable ID token/);
    });

    it('refuses several audiences when azp names another party', async () => {
      await expect(login({ sub: '1', claims: { azp: 'project-id' } })).rejects.toThrow(
        /unusable ID token/,
      );
    });

    it('accepts a single matching audience without azp', async () => {
      await expect(
        login({
          sub: '1',
          email: 'a@example.com',
          claims: { aud: issuer.clientId, azp: undefined },
        }),
      ).resolves.toMatchObject({ sub: '1' });
    });

    it('refuses an expired token', async () => {
      await expect(
        login({ sub: '1', claims: { exp: Math.floor(Date.now() / 1000) - 3600 } }),
      ).rejects.toThrow(/took too long/);
    });

    it('refuses a token issued in the future', async () => {
      await expect(
        login({ sub: '1', claims: { iat: Math.floor(Date.now() / 1000) + 3600 } }),
      ).rejects.toThrow(/unusable ID token/);
    });

    it('refuses a token whose nonce belongs to another login', async () => {
      await expect(login({ sub: '1', claims: { nonce: 'replayed' } })).rejects.toThrow(
        /unusable ID token/,
      );
    });

    it('refuses a token without a sub', async () => {
      await expect(login({ sub: '' })).rejects.toThrow(/unusable ID token/);
    });

    it('refuses alg none and HS256, whatever the header says', async () => {
      await expect(login({ sub: '1', header: { alg: 'none' } })).rejects.toThrow(
        /unusable ID token/,
      );
      await expect(login({ sub: '1', header: { alg: 'HS256' } })).rejects.toThrow(
        /unusable ID token/,
      );
    });

    it('refuses a token whose signature does not verify', async () => {
      const fetchMock = jest.fn(async (input: unknown, init?: RequestInit) => {
        const response = await issuer.fetch(input, init);
        if (!String(input).endsWith('/oauth/v2/token') || !response.ok) return response;
        const body = (await response.json()) as { id_token: string };
        const [header, payload] = body.id_token.split('.');
        const forged = Buffer.from(
          JSON.stringify({ ...JSON.parse(Buffer.from(payload, 'base64url').toString()), sub: '2' }),
        ).toString('base64url');
        const signature = body.id_token.split('.')[2];
        return Response.json({ id_token: `${header}.${forged}.${signature}` });
      });
      global.fetch = fetchMock as unknown as typeof fetch;
      await expect(login({ sub: '1' })).rejects.toThrow(/signature did not verify/);
    });

    it('refuses a token signed by a key the issuer does not publish', async () => {
      const other = new FakeOidcIssuer();
      const fetchMock = jest.fn(async (input: unknown, init?: RequestInit) => {
        const response = await issuer.fetch(input, init);
        if (!String(input).endsWith('/oauth/v2/token') || !response.ok) return response;
        const body = (await response.json()) as { id_token: string };
        const claims = JSON.parse(Buffer.from(body.id_token.split('.')[1], 'base64url').toString());
        return Response.json({ id_token: other.sign({ alg: 'RS256', kid: 'kid-1' }, claims) });
      });
      global.fetch = fetchMock as unknown as typeof fetch;
      await expect(login({ sub: '1' })).rejects.toThrow(/signature did not verify/);
    });

    it('re-fetches the key set once when the issuer has rotated its key', async () => {
      await login({ sub: '1', email: 'a@example.com' });
      expect(issuer.hits.jwks).toBe(1);
      issuer.rotateKey('kid-2');
      await expect(login({ sub: '1', email: 'a@example.com' })).resolves.toMatchObject({
        sub: '1',
      });
      expect(issuer.hits.jwks).toBe(2);
    });

    it('re-fetches the key set once after a rotation when the token carries no kid', async () => {
      await login({ sub: '1', email: 'a@example.com', header: { kid: undefined } });
      expect(issuer.hits.jwks).toBe(1);
      issuer.rotateKey('kid-2');
      // Every cached key is a candidate without a kid, so only a failed
      // signature, not an empty candidate list, can reveal the rotation.
      await expect(
        login({ sub: '1', email: 'a@example.com', header: { kid: undefined } }),
      ).resolves.toMatchObject({ sub: '1' });
      expect(issuer.hits.jwks).toBe(2);
    });

    it('does not fetch the key set twice when a just-fetched set fails the token', async () => {
      const other = new FakeOidcIssuer();
      const fetchMock = jest.fn(async (input: unknown, init?: RequestInit) => {
        const response = await issuer.fetch(input, init);
        if (!String(input).endsWith('/oauth/v2/token') || !response.ok) return response;
        const body = (await response.json()) as { id_token: string };
        const claims = JSON.parse(Buffer.from(body.id_token.split('.')[1], 'base64url').toString());
        return Response.json({ id_token: other.sign({ alg: 'RS256', kid: 'kid-1' }, claims) });
      });
      global.fetch = fetchMock as unknown as typeof fetch;
      await expect(login({ sub: '1' })).rejects.toThrow(/signature did not verify/);
      expect(issuer.hits.jwks).toBe(1);
    });

    it('shares one key-set fetch between concurrent logins after a rotation', async () => {
      await login({ sub: '1', email: 'a@example.com' });
      issuer.rotateKey('kid-2');
      const logins = ['c1', 'c2', 'c3'].map(async (code) => {
        const state = sealLoginState(`client_id=${code}`);
        issuer.approve(code, await loginRedirectUrl(config, 'zitadel', state), {
          sub: '1',
          email: 'a@example.com',
        });
        return state;
      });
      const states = await Promise.all(logins);
      await Promise.all(
        ['c1', 'c2', 'c3'].map((code, i) =>
          exchangeCodeForIdentity(config, 'zitadel', code, states[i]),
        ),
      );
      expect(issuer.hits.jwks).toBe(2);
    });

    it('refuses a key set without a keys array', async () => {
      issuer.jwksBody = { keys: 'not-an-array' };
      await expect(login({ sub: '1' })).rejects.toThrow(/unusable key set/);
    });

    it('refuses a malformed token', async () => {
      const fetchMock = jest.fn(async (input: unknown, init?: RequestInit) => {
        if (String(input).endsWith('/oauth/v2/token')) {
          return Response.json({ id_token: 'not-a-jwt' });
        }
        return issuer.fetch(input, init);
      });
      global.fetch = fetchMock as unknown as typeof fetch;
      await expect(login({ sub: '1' })).rejects.toThrow(/unusable ID token/);
    });
  });
});

describe('ZITADEL subjects stay apart from GitHub and Google', () => {
  it('keys a ZITADEL user separately from a Google user with the same sub and email', () => {
    expect(tenantKey({ provider: 'zitadel', sub: '42' })).not.toBe(
      tenantKey({ provider: 'google', sub: '42' }),
    );
    expect(tenantKey({ provider: 'zitadel', sub: '42' })).not.toBe(
      tenantKey({ provider: 'github', sub: '42' }),
    );
  });

  it('round-trips a ZITADEL identity through the enrolment ticket and the token subject', () => {
    const identity = { provider: 'zitadel' as const, sub: '42', login: 'a@example.com' };
    expect(openEnrolmentTicket(sealEnrolmentTicket(identity, 'q')).identity).toEqual(identity);
    expect(subjectFromAuthInfo({ provider: 'zitadel', sub: '42' })).toEqual({
      provider: 'zitadel',
      sub: '42',
    });
    expect(subjectFromAuthInfo({ provider: 'okta', sub: '42' })).toBeUndefined();
  });
});
