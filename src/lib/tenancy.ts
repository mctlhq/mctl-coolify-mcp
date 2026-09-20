/**
 * Multi-tenant mode: which Coolify does this caller reach?
 *
 * ## The one thing that makes this safe
 *
 * Upstream already builds a fresh `CoolifyMcpServer` per HTTP request —
 * `createMcpHandler` calls its factory once per request, and the SDK names this
 * exact use ("multi-tenant servers keyed off `authInfo`"). So tenancy is a
 * question of what the factory is handed, not of threading a tenant through 45
 * tools. A single shared instance would answer the second caller with the
 * first caller's access; a per-request one cannot.
 *
 * ## Trust model, and how it differs from upstream's
 *
 * Upstream's registry is a fleet: several instances, ONE trust domain, owned by
 * whoever configured the container. Here a registry belongs to one tenant and
 * is built from their own enrolment record. Two tenants are never in one
 * registry, so `instance: "all"` fans out across one tenant's instances and
 * can never reach another's.
 *
 * ## Why records are keyed by a hash
 *
 * The path is `users/<sha256(provider:sub)>`. The subject is not secret, but a
 * hash gives every path the same shape and character set, keeps a provider id
 * out of Vault's path listing and audit trail, and means no future provider
 * can produce a subject that needs escaping before it is a path.
 */
import { createHash } from 'node:crypto';
import { InstanceRegistry, type InstanceDefinition } from './instances.js';
import { VaultClient, VaultError } from './vault.js';
import type { VerifiedIdentity } from './identity.js';

/** A tenant's enrolled Coolify instances, as stored. */
export interface EnrolledInstance {
  name: string;
  baseUrl: string;
  accessToken: string;
}

export interface TenantRecord {
  instances: EnrolledInstance[];
  /** Epoch ms of the last write, for display on the enrolment page. */
  updatedAt: number;
  /** The login at enrolment time. Display and audit only, never a key. */
  login?: string;
}

export interface TenantStore {
  read(identity: Pick<VerifiedIdentity, 'provider' | 'sub'>): Promise<TenantRecord | undefined>;
  write(identity: VerifiedIdentity, record: TenantRecord): Promise<void>;
  revoke(identity: Pick<VerifiedIdentity, 'provider' | 'sub'>): Promise<void>;
}

export function tenantKey(identity: Pick<VerifiedIdentity, 'provider' | 'sub'>): string {
  return `users/${createHash('sha256').update(`${identity.provider}:${identity.sub}`).digest('hex')}`;
}

/**
 * The field name inside the Vault record.
 *
 * One JSON blob rather than a field per instance: the record is read and
 * written whole, and a single field keeps the KV version history — which
 * `max_versions=1` already caps at one — from depending on how many instances
 * a tenant happens to have.
 */
const RECORD_FIELD = 'instances_json';

export class VaultTenantStore implements TenantStore {
  constructor(private readonly vault: VaultClient) {}

  async read(
    identity: Pick<VerifiedIdentity, 'provider' | 'sub'>,
  ): Promise<TenantRecord | undefined> {
    const data = await this.vault.read(tenantKey(identity));
    const raw = data?.[RECORD_FIELD];
    // An empty string is what a revocation leaves behind between the
    // overwrite and the destroy. It means "no tenant", not "malformed".
    if (typeof raw !== 'string' || raw === '') return undefined;
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new VaultError('The stored enrolment record is not readable JSON.');
    }
    const record = parsed as TenantRecord;
    if (!Array.isArray(record?.instances)) return undefined;
    return record;
  }

  async write(identity: VerifiedIdentity, record: TenantRecord): Promise<void> {
    await this.vault.write(tenantKey(identity), { [RECORD_FIELD]: JSON.stringify(record) });
  }

  async revoke(identity: Pick<VerifiedIdentity, 'provider' | 'sub'>): Promise<void> {
    await this.vault.destroy(tenantKey(identity));
  }
}

/** In-memory store for tests and local development. */
export class MemoryTenantStore implements TenantStore {
  private readonly records = new Map<string, TenantRecord>();

  async read(
    identity: Pick<VerifiedIdentity, 'provider' | 'sub'>,
  ): Promise<TenantRecord | undefined> {
    return this.records.get(tenantKey(identity));
  }

  async write(identity: VerifiedIdentity, record: TenantRecord): Promise<void> {
    this.records.set(tenantKey(identity), record);
  }

  async revoke(identity: Pick<VerifiedIdentity, 'provider' | 'sub'>): Promise<void> {
    this.records.delete(tenantKey(identity));
  }
}

export class NotEnrolledError extends Error {
  constructor() {
    super('No Coolify instance is linked to this account.');
    this.name = 'NotEnrolledError';
  }
}

/**
 * Build the registry for one caller.
 *
 * Throws {@link NotEnrolledError} rather than returning an empty registry: an
 * empty one would give a caller 45 tools that all fail obscurely, where the
 * honest answer is that they have not linked an instance yet.
 *
 * Nothing is cached here. A cache would have to be invalidated by enrolment and
 * revocation, and a revocation that is still served from cache is the one
 * failure this store exists to prevent. The read is a single request to Vault
 * on a connection that is already warm; correctness is worth it.
 */
export async function registryForCaller(
  store: TenantStore,
  identity: Pick<VerifiedIdentity, 'provider' | 'sub'>,
): Promise<InstanceRegistry> {
  const record = await store.read(identity);
  if (!record || record.instances.length === 0) throw new NotEnrolledError();

  const definitions: InstanceDefinition[] = record.instances.map((instance) => ({
    name: instance.name,
    baseUrl: instance.baseUrl,
    accessToken: instance.accessToken,
  }));
  return new InstanceRegistry(definitions);
}

/**
 * The subject carried on a verified access token.
 *
 * `authInfo.extra` is the SDK's pass-through bag; the OAuth provider puts the
 * grant's subject there at issue time. A token without one cannot be served in
 * multi mode — it predates subject binding, and guessing which tenant it meant
 * is exactly the mistake that would cross two tenants.
 */
export function subjectFromAuthInfo(
  extra: unknown,
): Pick<VerifiedIdentity, 'provider' | 'sub'> | undefined {
  const bag = extra as { provider?: unknown; sub?: unknown } | undefined;
  if (!bag || typeof bag.provider !== 'string' || typeof bag.sub !== 'string') return undefined;
  if (bag.provider !== 'github') return undefined;
  return { provider: 'github', sub: bag.sub };
}
