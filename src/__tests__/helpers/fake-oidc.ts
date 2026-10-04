/**
 * A fake OIDC issuer (ZITADEL-shaped) for the identity tests: discovery, a
 * JWKS, and a token endpoint that checks client authentication and PKCE and
 * answers with an RS256 ID token signed by a real key. Only the network is
 * fake; every check the server makes runs against real signatures.
 */
import { createHash, createSign, generateKeyPairSync, type KeyObject } from 'node:crypto';

export const ZITADEL_ISSUER = 'https://auth.example.com';

export interface FakeLogin {
  sub: string;
  email?: string;
  /** Overrides applied to the ID token's claims, for negative tests. */
  claims?: Record<string, unknown>;
  /** Overrides applied to the ID token's header, for negative tests. */
  header?: Record<string, unknown>;
}

interface PendingCode extends FakeLogin {
  challenge: string;
  nonce: string;
}

export class FakeOidcIssuer {
  readonly issuer: string;
  readonly clientId: string;
  readonly clientSecret: string;
  private key: { privateKey: KeyObject; publicKey: KeyObject; kid: string };
  private readonly codes = new Map<string, PendingCode>();
  /** Overrides applied to the discovery document, for negative tests. */
  discovery: Record<string, unknown> = {};
  /** Set to a non-2xx status to make the discovery endpoint fail. */
  discoveryStatus = 200;
  /** Replaces the key-set response body, for negative tests. */
  jwksBody: unknown = undefined;
  /** How many times each endpoint was fetched. */
  readonly hits = { discovery: 0, jwks: 0, token: 0 };
  /** Token requests as received, for asserting what the server sent. */
  readonly tokenRequests: Array<{ authorization: string; body: URLSearchParams }> = [];

  /**
   * The defaults are ZITADEL-shaped on purpose: its client ids contain `@`,
   * and the secret holds characters that form-encoding changes, so the Basic
   * header's RFC 6749 §2.3.1 encoding is actually exercised.
   */
  constructor(
    issuer = ZITADEL_ISSUER,
    clientId = '290000000000000001@mctl',
    clientSecret = 'z-secret/with+reserved:chars%',
  ) {
    this.issuer = issuer;
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.key = FakeOidcIssuer.newKey('kid-1');
  }

  private static newKey(kid: string): { privateKey: KeyObject; publicKey: KeyObject; kid: string } {
    const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    return { privateKey, publicKey, kid };
  }

  /** Replace the signing key, as an issuer's key rotation would. */
  rotateKey(kid: string): void {
    this.key = FakeOidcIssuer.newKey(kid);
  }

  /**
   * Register what the next login with `code` returns. The challenge and nonce
   * are read off the authorize URL the server built, exactly as a real
   * issuer would remember them.
   */
  approve(code: string, authorizeUrl: string, login: FakeLogin): void {
    const url = new URL(authorizeUrl);
    this.codes.set(code, {
      ...login,
      challenge: url.searchParams.get('code_challenge') ?? '',
      nonce: url.searchParams.get('nonce') ?? '',
    });
  }

  sign(header: Record<string, unknown>, claims: Record<string, unknown>): string {
    const encode = (value: unknown): string =>
      Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
    const input = `${encode(header)}.${encode(claims)}`;
    const signature = createSign('RSA-SHA256').update(input).sign(this.key.privateKey);
    return `${input}.${signature.toString('base64url')}`;
  }

  fetch = async (input: unknown, init?: RequestInit): Promise<Response> => {
    const url = String(input);
    if (url === `${this.issuer}/.well-known/openid-configuration`) {
      this.hits.discovery++;
      if (this.discoveryStatus !== 200) {
        return new Response('unavailable', { status: this.discoveryStatus });
      }
      return Response.json({
        issuer: this.issuer,
        authorization_endpoint: `${this.issuer}/oauth/v2/authorize`,
        token_endpoint: `${this.issuer}/oauth/v2/token`,
        jwks_uri: `${this.issuer}/oauth/v2/keys`,
        ...this.discovery,
      });
    }
    if (url === `${this.issuer}/oauth/v2/keys`) {
      this.hits.jwks++;
      if (this.jwksBody !== undefined) return Response.json(this.jwksBody);
      const jwk = this.key.publicKey.export({ format: 'jwk' });
      return Response.json({ keys: [{ ...jwk, kid: this.key.kid, use: 'sig', alg: 'RS256' }] });
    }
    if (url === `${this.issuer}/oauth/v2/token`) {
      this.hits.token++;
      const headers = new Headers(init?.headers);
      const body = new URLSearchParams(String(init?.body ?? ''));
      const authorization = headers.get('authorization') ?? '';
      this.tokenRequests.push({ authorization, body });
      // Decode as ZITADEL does: base64, split at the first ':', then
      // form-decode each half (Go's url.QueryUnescape, so '+' is a space).
      const formDecode = (value: string): string | undefined => {
        try {
          return decodeURIComponent(value.replace(/\+/g, ' '));
        } catch {
          return undefined;
        }
      };
      const basic = Buffer.from(authorization.replace(/^Basic /, ''), 'base64').toString('utf8');
      const colon = basic.indexOf(':');
      const id = colon === -1 ? undefined : formDecode(basic.slice(0, colon));
      const secret = colon === -1 ? undefined : formDecode(basic.slice(colon + 1));
      if (
        !authorization.startsWith('Basic ') ||
        id !== this.clientId ||
        secret !== this.clientSecret
      ) {
        return Response.json({ error: 'invalid_client' }, { status: 401 });
      }
      const pending = this.codes.get(body.get('code') ?? '');
      const verifier = body.get('code_verifier') ?? '';
      const challenge = createHash('sha256').update(verifier).digest('base64url');
      if (!pending || pending.challenge !== challenge) {
        return Response.json({ error: 'invalid_grant' }, { status: 400 });
      }
      this.codes.delete(body.get('code') ?? '');
      const now = Math.floor(Date.now() / 1000);
      const idToken = this.sign(
        { alg: 'RS256', kid: this.key.kid, typ: 'JWT', ...pending.header },
        {
          iss: this.issuer,
          sub: pending.sub,
          aud: [this.clientId, 'project-id'],
          azp: this.clientId,
          exp: now + 3600,
          iat: now,
          nonce: pending.nonce,
          ...(pending.email !== undefined && { email: pending.email }),
          ...pending.claims,
        },
      );
      return Response.json({ access_token: 'zitadel-access', id_token: idToken });
    }
    throw new Error(`unexpected fetch in test: ${url}`);
  };
}
