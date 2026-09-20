/**
 * Identity for multi-tenant mode: who is the human behind this OAuth flow?
 *
 * ## Why this exists
 *
 * Upstream's authorize step is "tier-2 proof of access": the user pastes the
 * Coolify token of the one instance the container manages, it is validated
 * against `GET /teams/current` and discarded. That works precisely because
 * there is one instance and everyone who can prove access to it gets the same
 * privileges.
 *
 * A multi-tenant server has no such instance. Two callers must reach two
 * different Coolifys, so the flow has to answer a question upstream never
 * asks: *which tenant is this*. That answer has to survive across requests and
 * be unforgeable, which a pasted credential is not — so we delegate it to an
 * identity provider and keep only the resulting subject.
 *
 * ## What is deliberately not here
 *
 * No Coolify credential passes through this module, exactly as upstream's
 * `completeAuthorization` takes none. Identity says *who*; the enrolment
 * record says *what they may reach*. Keeping the two apart is what stops a
 * login from ever implying access to an instance.
 *
 * ## Why GitHub, and why the numeric id
 *
 * The subject is GitHub's **numeric user id**, never the login. Logins are
 * renameable and, once freed, claimable by someone else — keying tenants on
 * one would silently hand a tenant's stored Coolify token to whoever picked up
 * their abandoned handle. The id is immutable for the life of the account.
 */
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/** GitHub's OAuth endpoints. Fixed hosts, so no SSRF guard is warranted here. */
const GITHUB_AUTHORIZE = 'https://github.com/login/oauth/authorize';
const GITHUB_TOKEN = 'https://github.com/login/oauth/access_token';
const GITHUB_USER = 'https://api.github.com/user';

/**
 * How long a login may take from `/authorize` to the callback. Long enough for
 * a first-time user to be walked through GitHub's consent screen, short enough
 * that a state value leaked from browser history is useless by the time anyone
 * reads it.
 */
const STATE_TTL_SECONDS = 600;

/** Bound on an inbound state value, so a forged one cannot cost us memory. */
const MAX_STATE_BYTES = 8192;

/** Bound on a token or user response, for the same reason. */
const MAX_RESPONSE_BYTES = 64 * 1024;

/** Network budget for each leg of the exchange. */
const FETCH_TIMEOUT_MS = 10_000;

export interface IdentityConfig {
  clientId: string;
  clientSecret: string;
  /** Absolute URL GitHub redirects back to, i.e. `${publicUrl}/auth/github/callback`. */
  callbackUrl: string;
}

/** The verified human. `sub` is what tenant records are keyed by. */
export interface VerifiedIdentity {
  provider: 'github';
  /** GitHub's immutable numeric user id, as a string. Never the login. */
  sub: string;
  /** Current login, carried for display and audit only — never used as a key. */
  login: string;
}

export class IdentityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'IdentityError';
  }
}

/**
 * Read the identity provider's credentials from the environment.
 *
 * Returns `undefined` when unconfigured rather than throwing, so single-tenant
 * mode — which needs no identity provider at all — boots unchanged. Multi
 * mode's startup check is what turns absence into a refusal to start.
 */
export function identityFromEnv(
  env: NodeJS.ProcessEnv,
  publicUrl: string,
): IdentityConfig | undefined {
  const clientId = env.GITHUB_CLIENT_ID?.trim();
  const clientSecret = env.GITHUB_CLIENT_SECRET?.trim();
  if (!clientId || !clientSecret) return undefined;
  return { clientId, clientSecret, callbackUrl: `${publicUrl}/auth/github/callback` };
}

// ---------------------------------------------------------------------------
// Signed state
// ---------------------------------------------------------------------------

/**
 * The HMAC key for the login state.
 *
 * Same key and same discipline as the confirmation codec in `elicit.ts`:
 * `MCP_REQUEST_STATE_KEY` when set, otherwise one generated per process. The
 * generated fallback fails closed — a login in flight across a restart is
 * refused and the user logs in again — so it is an availability trade, not a
 * security one. Set the variable to survive restarts and to run more than one
 * replica.
 *
 * Per process, not per call: a key minted per request would differ between the
 * round that seals the state and the round that opens it, and every login
 * would fail as forged.
 */
let generatedKey: Buffer | undefined;

function stateKey(): Buffer | string {
  const configured = process.env.MCP_REQUEST_STATE_KEY;
  if (configured === undefined || configured === '') {
    if (generatedKey === undefined) generatedKey = randomBytes(32);
    return generatedKey;
  }
  if (Buffer.byteLength(configured, 'utf8') < 32) {
    throw new Error(
      'MCP_REQUEST_STATE_KEY must be at least 32 bytes. Generate one with: openssl rand -hex 32',
    );
  }
  return configured;
}

function b64url(value: Buffer): string {
  return value.toString('base64url');
}

function sign(payload: string): string {
  return b64url(createHmac('sha256', stateKey()).update(payload).digest());
}

/**
 * Seal a short-lived value that travels through the user's browser.
 *
 * Signed, not encrypted. Two things ride on this: the client's own OAuth
 * request across the trip to GitHub, and — after the login — the identity we
 * just established, carried into the enrolment form. Neither is secret to the
 * person holding it: the first is the client's own request, the second is who
 * they just proved they are. No credential ever goes in here.
 *
 * What the signature buys is integrity. Without it a redirect could be
 * re-pointed, a `code_challenge` swapped for the attacker's own, or — worse —
 * a subject edited, which would file one tenant's Coolify token under another
 * tenant's name. The nonce distinguishes otherwise identical flows in logs;
 * the expiry bounds how long a value left in browser history stays usable.
 */
export function sealTicket(
  claims: Record<string, unknown>,
  ttlSeconds = STATE_TTL_SECONDS,
): string {
  const payload = b64url(
    Buffer.from(
      JSON.stringify({
        ...claims,
        exp: Math.floor(Date.now() / 1000) + ttlSeconds,
        n: b64url(randomBytes(9)),
      }),
      'utf8',
    ),
  );
  return `${payload}.${sign(payload)}`;
}

/**
 * Open a ticket that came back through the browser, i.e. attacker-controlled
 * input. Throws on anything that is not a currently-valid ticket we minted.
 */
export function openTicket(value: string): Record<string, unknown> {
  if (!value || Buffer.byteLength(value, 'utf8') > MAX_STATE_BYTES) {
    throw new IdentityError('The login state is missing or malformed.');
  }
  const separator = value.lastIndexOf('.');
  if (separator <= 0) throw new IdentityError('The login state is malformed.');

  const payload = value.slice(0, separator);
  const presented = Buffer.from(value.slice(separator + 1), 'utf8');
  const expected = Buffer.from(sign(payload), 'utf8');
  // Length must match before timingSafeEqual, which throws on a mismatch
  // rather than returning false.
  if (presented.length !== expected.length || !timingSafeEqual(presented, expected)) {
    throw new IdentityError('The login state failed verification.');
  }

  let decoded: unknown;
  try {
    decoded = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  } catch {
    throw new IdentityError('The login state is malformed.');
  }
  const claims = decoded as Record<string, unknown>;
  if (typeof claims?.exp !== 'number') throw new IdentityError('The login state is malformed.');
  if (claims.exp < Math.floor(Date.now() / 1000)) {
    throw new IdentityError('The login took too long. Start again.');
  }
  return claims;
}

/** The login leg: carries the client's original authorization request. */
export function sealLoginState(originalQuery: string): string {
  return sealTicket({ q: originalQuery });
}

export function openLoginState(value: string): { query: string } {
  const claims = openTicket(value);
  if (typeof claims.q !== 'string') throw new IdentityError('The login state is malformed.');
  return { query: claims.q };
}

/**
 * The enrolment leg: carries the identity just established, so the enrolment
 * form works without a cookie or a session — the same stateless shape as the
 * upstream authorize form, which carries its whole state in the form body.
 */
export function sealEnrolmentTicket(identity: VerifiedIdentity, originalQuery: string): string {
  return sealTicket({
    provider: identity.provider,
    sub: identity.sub,
    login: identity.login,
    q: originalQuery,
  });
}

export function openEnrolmentTicket(value: string): {
  identity: VerifiedIdentity;
  query: string;
} {
  const claims = openTicket(value);
  if (
    claims.provider !== 'github' ||
    typeof claims.sub !== 'string' ||
    typeof claims.login !== 'string' ||
    typeof claims.q !== 'string'
  ) {
    throw new IdentityError('The enrolment session is malformed. Start again.');
  }
  return {
    identity: { provider: 'github', sub: claims.sub, login: claims.login },
    query: claims.q,
  };
}

// ---------------------------------------------------------------------------
// The OAuth legs
// ---------------------------------------------------------------------------

/**
 * Where to send the browser to log in.
 *
 * No scopes are requested. We want a name, not access: an unscoped GitHub
 * token reads public profile data and nothing else, so a compromise of this
 * server cannot turn into a compromise of anyone's repositories.
 */
export function loginRedirectUrl(config: IdentityConfig, state: string): string {
  const params = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: config.callbackUrl,
    state,
    scope: '',
    allow_signup: 'false',
  });
  return `${GITHUB_AUTHORIZE}?${params.toString()}`;
}

async function readCapped(response: Response): Promise<string> {
  const text = await response.text();
  if (Buffer.byteLength(text, 'utf8') > MAX_RESPONSE_BYTES) {
    throw new IdentityError('The identity provider returned an implausibly large response.');
  }
  return text;
}

/**
 * Exchange the callback's `code` for the caller's identity.
 *
 * Two legs, both against fixed GitHub hosts: the code becomes an access token,
 * the access token names a user. The token is used for that one request and
 * then dropped — it is never stored, never returned and never used to act,
 * which is the same property upstream gives the Coolify token it validates.
 */
export async function exchangeCodeForIdentity(
  config: IdentityConfig,
  code: string,
): Promise<VerifiedIdentity> {
  if (!code) throw new IdentityError('The identity provider returned no authorization code.');

  const tokenResponse = await fetch(GITHUB_TOKEN, {
    method: 'POST',
    headers: { accept: 'application/json', 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: config.clientId,
      client_secret: config.clientSecret,
      code,
      redirect_uri: config.callbackUrl,
    }).toString(),
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  }).catch(() => {
    throw new IdentityError('Could not reach the identity provider. Try again.');
  });

  if (!tokenResponse.ok) throw new IdentityError('The identity provider rejected the login.');

  let token: unknown;
  try {
    token = JSON.parse(await readCapped(tokenResponse));
  } catch {
    throw new IdentityError('The identity provider returned an unreadable response.');
  }
  const parsed = token as { access_token?: unknown; error?: unknown };
  // GitHub answers 200 with an `error` field rather than a 4xx, so the status
  // check above is not enough on its own.
  if (typeof parsed.access_token !== 'string' || parsed.access_token === '') {
    throw new IdentityError('The identity provider did not issue a token.');
  }

  const userResponse = await fetch(GITHUB_USER, {
    headers: {
      accept: 'application/vnd.github+json',
      authorization: `Bearer ${parsed.access_token}`,
      'user-agent': 'mctl-coolify-mcp',
    },
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  }).catch(() => {
    throw new IdentityError('Could not reach the identity provider. Try again.');
  });

  if (!userResponse.ok) throw new IdentityError('The identity provider would not name the user.');

  let user: unknown;
  try {
    user = JSON.parse(await readCapped(userResponse));
  } catch {
    throw new IdentityError('The identity provider returned an unreadable profile.');
  }
  const profile = user as { id?: unknown; login?: unknown };
  if (typeof profile.id !== 'number' || typeof profile.login !== 'string') {
    throw new IdentityError('The identity provider returned an unusable profile.');
  }

  return { provider: 'github', sub: String(profile.id), login: profile.login };
}
