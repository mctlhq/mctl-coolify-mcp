# Multi-tenant mode: one hosted server, every tenant brings their own Coolify

This is a fork-specific addition on top of upstream's [HTTP mode](http-mode.md).
Everything in that document — the OAuth 2.1 authorization server, the 45
tools, the audit log, the SSRF guard — is unchanged and still describes how a
single container serving one Coolify (or one owner's fleet) behaves. This
document describes the second mode this fork adds: `MCP_TENANCY=multi`, where
one deployment serves any number of unrelated tenants, each with their own
Coolify instance and their own credential, and no tenant can reach another's.

## Why this exists

Upstream's HTTP mode answers "how do I let claude.ai manage the Coolify I
already run." It does that by making the container hold one Coolify token as
configuration; the OAuth flow authenticates a human, and that human's own
Coolify token is the proof they may use it — validated once at `/authorize`
and immediately discarded. That is exactly right for the deployment it is
built for: "an agency with a Coolify per client runs one container per
client; the isolation is the deployment, not the OAuth layer" (see the fleet
note in [http-mode.md](http-mode.md#running-a-fleet-over-http)).

Multi-tenant mode is for the different question: "I want to run **one**
public service that anyone can connect to from claude.ai, sign in, and manage
**their own** Coolify." Nothing upstream, and nothing else we could find on
GitHub or npm, does that — every existing Coolify MCP server, ours included
until this fork, assumes the operator and the Coolify owner are the same
person.

## What changes

|                                    | Single-tenant (`MCP_TENANCY=single`, the default)         | Multi-tenant (`MCP_TENANCY=multi`)                                                           |
| ---------------------------------- | --------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| Who the OAuth flow authenticates   | Whoever can prove they hold the container's Coolify token | Whoever can sign in with GitHub                                                              |
| Whose Coolify a tool call reaches  | The one in `COOLIFY_BASE_URL` / `COOLIFY_INSTANCES`       | Whichever the signed-in caller enrolled                                                      |
| Where the Coolify credential lives | Container environment                                     | Vault, keyed by the caller, entered once through `/enroll`                                   |
| `/authorize`                       | Asks for a Coolify token                                  | Redirects to GitHub                                                                          |
| New routes                         | —                                                         | `/enroll`, `/auth/github/callback`, `/enroll/revoke`                                         |
| OAuth state persistence            | A file on a mounted volume (`MCP_OAUTH_STATE_FILE`)       | The same file, but under `/tmp`, mirrored to Vault so it survives a restart without a volume |

Everything else — the 45 tools, PKCE, CIMD/DCR client registration, the
destructive-operation guard, the audit log — behaves identically in both
modes, because both are the same `CoolifyMcpServer` and the same
`OAuthProvider`; only what builds the Coolify instance registry for a given
caller differs.

## Setup

You need:

- A **GitHub OAuth App** (Settings → Developer settings → OAuth Apps →
  New OAuth App). Set its callback URL to `${MCP_PUBLIC_URL}/auth/github/callback`
  — the server prints the exact value it expects if you start it without one
  configured. No scopes are requested at sign-in; the app only needs to name
  who is signing in.
- A **Vault KV v2 mount** the container can reach, with `max_versions=1` (see
  [why](#why-max_versions1), below), and a policy that lets the container's
  identity read and write under it. Kubernetes auth is what this fork's own
  deployment uses; a static token (`VAULT_TOKEN`) works for local development.

```bash
MCP_TRANSPORT=http
MCP_TENANCY=multi
MCP_PUBLIC_URL=https://coolify-mcp.example.com

GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...

VAULT_ADDR=https://vault.example.com
VAULT_KV_MOUNT=coolify-mcp-users
VAULT_ROLE=coolify-mcp            # Kubernetes auth; use VAULT_TOKEN outside a cluster
# VAULT_AUTH_MOUNT=kubernetes     # only if your Kubernetes auth mount isn't the default path
# VAULT_K8S_TOKEN_PATH=...        # only if the projected service-account token isn't the default path

# Optional: shown to a signed-in tenant on /enroll only, never published.
# See "if a tenant's Coolify restricts API access by IP" below.
MCP_EGRESS_ADDRESSES=203.0.113.10,203.0.113.11
```

Notice `COOLIFY_BASE_URL` and `COOLIFY_ACCESS_TOKEN` are **absent**: the
operator of a multi-tenant server need not own a Coolify at all. The server
refuses to start without `GITHUB_CLIENT_ID`/`GITHUB_CLIENT_SECRET` and
`VAULT_ADDR`/`VAULT_KV_MOUNT`, naming exactly what is missing, rather than
booting and failing the first person who tries to connect.

## What a tenant does

1. Add the server as a custom connector in claude.ai (or any MCP client) at
   `https://coolify-mcp.example.com/mcp`, same as upstream.
2. Instead of a Coolify-token form, `/authorize` sends them to GitHub.
3. First time through, they land on `/enroll`: a name for the instance
   (`default` unless they run more than one), their Coolify's address, and a
   Coolify API token created under **Keys & Tokens → API tokens**. The page
   recommends the least privilege the intended use needs — `read` alone to
   inspect, add `deploy` to deploy, avoid `root` — the same permissions
   [upstream's security guide](security.md) already documents.
4. The server proves the address and token actually work (`GET
/api/v1/teams/current`) before storing anything, and before completing
   whatever OAuth request brought them there.
5. From then on, `/enroll` (reachable any time by signing in again) lists
   what is linked and can unlink it. Unlinking **destroys** the stored
   credential — not a soft delete — and takes effect on the tenant's very
   next tool call.

## If a tenant's Coolify restricts API access by IP

Coolify has an optional "Allowed API IPs" setting (off by default). A tenant
who has turned it on needs to allow the address this server connects from.
That address is shown to them on `/enroll` (`MCP_EGRESS_ADDRESSES` above) —
**deliberately not published anywhere else.** This server sits behind a CDN
on purpose; the addresses it actually connects from are its real origin, and
publishing them would hand that origin to anyone scanning for it, for no
benefit to a tenant who never turned the setting on in the first place.

## Isolation, and how it is tested

Two tenants are never in one Coolify instance registry: each request's
registry is built fresh from the caller's own enrolment record, the same
per-request-server-construction the MCP SDK already provides upstream (see
the "the property upstream already has" note in the code). Concretely:

- **A tenant's stored address is re-validated on every request, not just at
  enrolment.** A tenant who enrolls a domain they control could, in
  principle, repoint its DNS at an internal address after enrolling. Every
  tool call re-resolves the address, refuses anything private, and pins the
  connection to what it just resolved — the same guard upstream's own SSRF
  protection applies to client metadata documents, applied here to every
  tenant Coolify call.
- **Revocation destroys, it does not merely mark deleted** — the same
  distinction Vault's own KV v2 makes between `delete` (a tombstone; earlier
  versions stay readable) and `destroy`.
- **A test suite enumerates the isolation property directly**: given two
  tenants with different Coolify instances, no tool call under one tenant's
  token can be made to return the other's data, and a DNS-rebinding attempt
  is refused by name, not silently ignored.

### Why `max_versions=1`

`vault kv delete` on a KV v2 mount hides the current version; it does not
remove it, and every prior version stays readable to anyone with read access
to the mount. A revocation implemented with `delete` alone would not revoke.
This fork's revocation overwrites with an empty record and then destroys
every version that ever existed — but "every version that ever existed" is
only ever one if the mount enforces `max_versions=1` in the first place.

## What does not change from upstream

- **Destructive operations still refuse without elicitation.** claude.ai
  cannot elicit, so in both modes it gets the read-and-safe-write surface
  only, exactly as [upstream describes](http-mode.md#destructive-operations-require-a-human).
- **The audit log** gains one field, `subject` — the enrolled tenant a call
  ran on behalf of, alongside the existing `client_id` (which names the
  _app_ that connected, the same for every tenant using it). Absent in
  single-tenant mode.
- **A Coolify behind a VPN or on a private network cannot be reached by a
  hosted multi-tenant server**, for the same reason it cannot be reached by
  any other internet-facing service: there is no route to it. Run this
  server yourself, in single-tenant mode, on your own network instead — see
  [Install](../README.md#install) and
  [Running outside a container](http-mode.md#running-outside-a-container).
