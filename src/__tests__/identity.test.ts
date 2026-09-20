import { jest } from '@jest/globals';
import {
  IdentityError,
  configuredProviders,
  exchangeCodeForIdentity,
  identityFromEnv,
  loginRedirectUrl,
  openLoginState,
  sealLoginState,
  type IdentityConfig,
} from '../lib/identity.js';

const githubCreds = {
  clientId: 'Iv1.deadbeef',
  clientSecret: 'shhh',
  callbackUrl: 'https://coolify.mctl.ai/auth/github/callback',
};
const config: IdentityConfig = { github: githubCreds };

const googleCreds = {
  clientId: 'g-client.apps.googleusercontent.com',
  clientSecret: 'g-shhh',
  callbackUrl: 'https://coolify.mctl.ai/auth/google/callback',
};
const bothConfig: IdentityConfig = { github: githubCreds, google: googleCreds };

/** A fixed key, so sealing and opening agree without relying on the generated fallback. */
const KEY = 'k'.repeat(48);

beforeEach(() => {
  process.env.MCP_REQUEST_STATE_KEY = KEY;
});

afterEach(() => {
  delete process.env.MCP_REQUEST_STATE_KEY;
  jest.restoreAllMocks();
});

describe('identity configuration', () => {
  it('is undefined when unset, so single-tenant mode boots without one', () => {
    expect(identityFromEnv({}, 'https://coolify.mctl.ai')).toBeUndefined();
    expect(
      identityFromEnv({ GITHUB_CLIENT_ID: 'only-half' }, 'https://coolify.mctl.ai'),
    ).toBeUndefined();
  });

  it('derives the callback from the public URL', () => {
    const resolved = identityFromEnv(
      { GITHUB_CLIENT_ID: ' Iv1.deadbeef ', GITHUB_CLIENT_SECRET: ' shhh ' },
      'https://coolify.mctl.ai',
    );
    expect(resolved).toEqual({ github: githubCreds, google: undefined });
  });

  it('configures either provider independently, and both together', () => {
    expect(
      identityFromEnv(
        { GOOGLE_CLIENT_ID: googleCreds.clientId, GOOGLE_CLIENT_SECRET: googleCreds.clientSecret },
        'https://coolify.mctl.ai',
      ),
    ).toEqual({ github: undefined, google: googleCreds });

    expect(
      identityFromEnv(
        {
          GITHUB_CLIENT_ID: githubCreds.clientId,
          GITHUB_CLIENT_SECRET: githubCreds.clientSecret,
          GOOGLE_CLIENT_ID: googleCreds.clientId,
          GOOGLE_CLIENT_SECRET: googleCreds.clientSecret,
        },
        'https://coolify.mctl.ai',
      ),
    ).toEqual(bothConfig);
  });
});

describe('configured providers', () => {
  it('lists only what is actually configured, github before google', () => {
    expect(configuredProviders(config)).toEqual(['github']);
    expect(configuredProviders({ google: googleCreds })).toEqual(['google']);
    expect(configuredProviders(bothConfig)).toEqual(['github', 'google']);
    expect(configuredProviders({})).toEqual([]);
  });
});

describe('login state', () => {
  it('round-trips the original authorization request', () => {
    const query = 'client_id=abc&redirect_uri=https%3A%2F%2Fclaude.ai%2Fapi%2Fmcp%2Fauth_callback';
    expect(openLoginState(sealLoginState(query)).query).toBe(query);
  });

  it('refuses a payload whose signature does not match', () => {
    const sealed = sealLoginState('client_id=abc');
    const [payload, signature] = sealed.split('.');
    // Re-point the redirect and keep the old signature: the attack the
    // signature exists to stop.
    const forged = Buffer.from(
      JSON.stringify({ q: 'client_id=attacker', exp: 2 ** 31, n: 'x' }),
      'utf8',
    ).toString('base64url');
    expect(() => openLoginState(`${forged}.${signature}`)).toThrow(IdentityError);
    expect(openLoginState(`${payload}.${signature}`).query).toBe('client_id=abc');
  });

  it('refuses state signed with a different key', () => {
    const sealed = sealLoginState('client_id=abc');
    process.env.MCP_REQUEST_STATE_KEY = 'z'.repeat(48);
    expect(() => openLoginState(sealed)).toThrow(/failed verification/);
  });

  it('refuses expired state', () => {
    const sealed = sealLoginState('client_id=abc');
    jest.spyOn(Date, 'now').mockReturnValue(Date.now() + 601_000);
    expect(() => openLoginState(sealed)).toThrow(/took too long/);
  });

  it('refuses malformed, empty and oversized values without parsing them', () => {
    expect(() => openLoginState('')).toThrow(IdentityError);
    expect(() => openLoginState('no-separator')).toThrow(IdentityError);
    expect(() => openLoginState('.sig')).toThrow(IdentityError);
    expect(() => openLoginState(`${'a'.repeat(9000)}.sig`)).toThrow(IdentityError);
  });

  it('rejects a short signing key rather than signing weakly', () => {
    process.env.MCP_REQUEST_STATE_KEY = 'tooshort';
    expect(() => sealLoginState('client_id=abc')).toThrow(/at least 32 bytes/);
  });
});

describe('login redirect', () => {
  it('asks GitHub for no scopes, because we want a name and not access', () => {
    const url = new URL(loginRedirectUrl(config, 'github', 'state-value'));
    expect(url.origin + url.pathname).toBe('https://github.com/login/oauth/authorize');
    expect(url.searchParams.get('scope')).toBe('');
    expect(url.searchParams.get('client_id')).toBe(githubCreds.clientId);
    expect(url.searchParams.get('redirect_uri')).toBe(githubCreds.callbackUrl);
    expect(url.searchParams.get('state')).toBe('state-value');
  });

  it('asks Google for openid + email only, not profile', () => {
    const url = new URL(loginRedirectUrl(bothConfig, 'google', 'state-value'));
    expect(url.origin + url.pathname).toBe('https://accounts.google.com/o/oauth2/v2/auth');
    expect(url.searchParams.get('scope')).toBe('openid email');
    expect(url.searchParams.get('client_id')).toBe(googleCreds.clientId);
    expect(url.searchParams.get('redirect_uri')).toBe(googleCreds.callbackUrl);
    expect(url.searchParams.get('state')).toBe('state-value');
  });

  it('refuses to build a link for a provider that is not configured', () => {
    expect(() => loginRedirectUrl(config, 'google', 'state-value')).toThrow(
      /google login is not configured/,
    );
  });
});

describe('code exchange', () => {
  function mockFetch(...responses: Array<{ ok?: boolean; body: unknown }>): jest.Mock {
    const fetchMock = jest.fn();
    for (const { ok = true, body } of responses) {
      fetchMock.mockResolvedValueOnce({
        ok,
        text: async () => (typeof body === 'string' ? body : JSON.stringify(body)),
      } as never);
    }
    global.fetch = fetchMock as unknown as typeof fetch;
    return fetchMock;
  }

  it('returns the numeric id as the subject, never the renameable login', async () => {
    mockFetch(
      { body: { access_token: 'gho_x' } },
      { body: { id: 583231, login: 'octocat', name: 'The Octocat' } },
    );
    await expect(exchangeCodeForIdentity(config, 'github', 'the-code')).resolves.toEqual({
      provider: 'github',
      sub: '583231',
      login: 'octocat',
    });
  });

  it('does not carry the provider token out of the module', async () => {
    mockFetch({ body: { access_token: 'gho_secret' } }, { body: { id: 1, login: 'a' } });
    const identity = await exchangeCodeForIdentity(config, 'github', 'the-code');
    expect(JSON.stringify(identity)).not.toContain('gho_secret');
  });

  it('treats a 200 carrying an error field as a failure', async () => {
    // GitHub answers 200 with `error` rather than a 4xx, so a status check
    // alone would accept this.
    mockFetch({ body: { error: 'bad_verification_code' } });
    await expect(exchangeCodeForIdentity(config, 'github', 'stale')).rejects.toThrow(
      /did not issue a token/,
    );
  });

  it('refuses a profile without a numeric id', async () => {
    mockFetch({ body: { access_token: 'gho_x' } }, { body: { login: 'octocat' } });
    await expect(exchangeCodeForIdentity(config, 'github', 'the-code')).rejects.toThrow(
      /unusable profile/,
    );
  });

  it('refuses an empty code without calling out', async () => {
    const fetchMock = mockFetch();
    await expect(exchangeCodeForIdentity(config, 'github', '')).rejects.toThrow(
      /no authorization code/,
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('reports an unreachable provider as such', async () => {
    const fetchMock = jest.fn<() => Promise<never>>().mockRejectedValue(new Error('ECONNREFUSED'));
    global.fetch = fetchMock as unknown as typeof fetch;
    await expect(exchangeCodeForIdentity(config, 'github', 'the-code')).rejects.toThrow(
      /Could not reach/,
    );
  });

  it('refuses an implausibly large response instead of holding it', async () => {
    mockFetch({ body: 'x'.repeat(70 * 1024) });
    await expect(exchangeCodeForIdentity(config, 'github', 'the-code')).rejects.toThrow(
      /implausibly large|unreadable/,
    );
  });

  it('refuses to exchange for a provider that is not configured', async () => {
    const fetchMock = mockFetch();
    await expect(exchangeCodeForIdentity(config, 'google', 'the-code')).rejects.toThrow(
      /google login is not configured/,
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  describe('google', () => {
    it('returns the OIDC sub as the subject and the email as the display login', async () => {
      mockFetch(
        { body: { access_token: 'ya29.x' } },
        {
          body: { sub: '110169484474386276334', email: 'person@example.com', email_verified: true },
        },
      );
      await expect(exchangeCodeForIdentity(bothConfig, 'google', 'the-code')).resolves.toEqual({
        provider: 'google',
        sub: '110169484474386276334',
        login: 'person@example.com',
      });
    });

    it('refuses a profile missing sub or email', async () => {
      mockFetch({ body: { access_token: 'ya29.x' } }, { body: { email: 'person@example.com' } });
      await expect(exchangeCodeForIdentity(bothConfig, 'google', 'the-code')).rejects.toThrow(
        /unusable profile/,
      );
    });

    it('does not carry the provider token out of the module', async () => {
      mockFetch(
        { body: { access_token: 'ya29.secret' } },
        { body: { sub: '1', email: 'a@example.com' } },
      );
      const identity = await exchangeCodeForIdentity(bothConfig, 'google', 'the-code');
      expect(JSON.stringify(identity)).not.toContain('ya29.secret');
    });
  });
});
