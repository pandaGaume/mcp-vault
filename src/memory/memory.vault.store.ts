import { VaultError, notFound } from "../contract/errors";
import type { ISecretStore } from "../contract/vault.store";
import type {
    IDeleteSecretRequest,
    IDeleteSecretResult,
    IListSecretsRequest,
    IListSecretsResult,
    IReadSecretRequest,
    ISecretContent,
    ISecretEntry,
    ISecretSummary,
    IShareSecretRequest,
    IVaultCapabilities,
    IWriteSecretRequest,
    IWriteSecretResult,
    SecretPath,
} from "../contract/vault.types";
import { isUnder, parseAudiences, parseCas, parseContent, parseLimit, parsePrefix, parseSecretPath, parseVersion } from "../contract/validation";

export interface IMemoryVaultStoreOptions {
    readonly id?: string;
    readonly maxContentBytes?: number;
    readonly listLimit?: number;
    /** The clock, for tests. */
    readonly now?: () => number;
}

interface IRecord {
    readonly versions: { readonly content: ISecretContent; readonly createdTime: string }[];
    audiences: string[];
    readonly createdTime: string;
    updatedTime: string;
}

/**
 * Secrets in memory, lost with the process. For tests and benches; the
 * reference every other store is measured against.
 */
export class MemoryVaultStore implements ISecretStore {
    readonly id: string;
    private readonly _records = new Map<SecretPath, IRecord>();
    private readonly _maxContentBytes: number;
    private readonly _listLimit: number;
    private readonly _now: () => number;

    constructor(options: IMemoryVaultStoreOptions = {}) {
        this.id = options.id ?? "memory";
        this._maxContentBytes = options.maxContentBytes ?? 512 * 1024;
        this._listLimit = options.listLimit ?? 1000;
        this._now = options.now ?? Date.now;
    }

    async getCapabilitiesAsync(): Promise<IVaultCapabilities> {
        return { backend: "memory", versioning: true, maxContentBytes: this._maxContentBytes, listLimit: this._listLimit };
    }

    async readAsync(request: IReadSecretRequest): Promise<ISecretEntry> {
        const path = parseSecretPath(request.path);
        const version = parseVersion(request.version);
        const record = this._records.get(path);
        if (!record) throw notFound(path);
        const index = (version ?? record.versions.length) - 1;
        const found = record.versions[index];
        if (!found) throw new VaultError("not_found", `secret "${path}" has no version ${version}`);
        return { path, version: index + 1, createdTime: found.createdTime, content: structuredClone(found.content) };
    }

    async writeAsync(request: IWriteSecretRequest): Promise<IWriteSecretResult> {
        const path = parseSecretPath(request.path);
        const cas = parseCas(request.cas);
        const content = parseContent(request.content, this._maxContentBytes);
        const record = this._records.get(path);
        const current = record?.versions.length ?? 0;
        if (cas !== undefined && cas !== current)
            throw new VaultError("conflict", `secret "${path}" is at version ${current}, not ${cas}`, { detail: { currentVersion: current } });
        const time = new Date(this._now()).toISOString();
        if (record) {
            record.versions.push({ content, createdTime: time });
            record.updatedTime = time;
        } else {
            this._records.set(path, { versions: [{ content, createdTime: time }], audiences: [], createdTime: time, updatedTime: time });
        }
        return { path, version: current + 1 };
    }

    async listAsync(request: IListSecretsRequest): Promise<IListSecretsResult> {
        const prefix = parsePrefix(request.prefix);
        const limit = parseLimit(request.limit, this._listLimit);
        const paths = [...this._records.keys()].filter((path) => isUnder(path, prefix)).sort();
        return { items: paths.slice(0, limit).map((path) => this._summary(path, this._records.get(path)!)), truncated: paths.length > limit };
    }

    async describeAsync(path: SecretPath): Promise<ISecretSummary> {
        const parsed = parseSecretPath(path);
        const record = this._records.get(parsed);
        if (!record) throw notFound(parsed);
        return this._summary(parsed, record);
    }

    async shareAsync(request: IShareSecretRequest): Promise<ISecretSummary> {
        const path = parseSecretPath(request.path);
        const audiences = parseAudiences(request.audiences);
        const record = this._records.get(path);
        if (!record) throw notFound(path);
        record.audiences = audiences;
        return this._summary(path, record);
    }

    async deleteAsync(request: IDeleteSecretRequest): Promise<IDeleteSecretResult> {
        const path = parseSecretPath(request.path);
        const record = this._records.get(path);
        if (!record) throw notFound(path);
        this._records.delete(path);
        return { path, versions: record.versions.length };
    }

    async closeAsync(): Promise<void> {
        this._records.clear();
    }

    private _summary(path: SecretPath, record: IRecord): ISecretSummary {
        return {
            path,
            kind: record.versions[record.versions.length - 1]!.content.kind,
            currentVersion: record.versions.length,
            createdTime: record.createdTime,
            updatedTime: record.updatedTime,
            audiences: [...record.audiences],
        };
    }
}
