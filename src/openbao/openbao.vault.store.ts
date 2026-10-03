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
    SecretKind,
    SecretPath,
} from "../contract/vault.types";
import {
    RESERVED_KEY_PREFIX,
    isAudience,
    isPlainObject,
    parseAudiences,
    parseCas,
    parseContent,
    parseLimit,
    parsePrefix,
    parseSecretPath,
    parseVersion,
    toIsoInstant,
} from "../contract/validation";

/** Custom metadata keys this store owns on each secret; any other key is left as it is. */
export const OPENBAO_METADATA_KEYS = { kind: "mcp-vault.kind", audiences: "mcp-vault.audiences" } as const;

/** Marks a version that holds a file, inside its KV data, so a version always says what it is. */
const FILE_MARK = `${RESERVED_KEY_PREFIX}kind`;

/** OpenBao's bound on a custom metadata value. */
const MAX_METADATA_VALUE = 512;

/** How far `list` walks a mount before giving up. */
const MAX_WALK = 10_000;

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);

export interface IOpenBaoVaultStoreOptions {
    /** For instance `https://bao.site1.local:8200`. */
    readonly address: string;
    /** A token restricted to this store's path (OpenBao policy), or a function that returns a fresh one (AppRole, Kubernetes auth...). */
    readonly token: string | (() => string | Promise<string>);
    /** The KV version 2 mount. `secret` by default. */
    readonly mount?: string;
    /** A path inside the mount that holds every secret of this store, e.g. `mcp-vault/site1`. */
    readonly prefix?: string;
    /** OpenBao namespace, sent as `X-Vault-Namespace`. */
    readonly namespace?: string;
    /**
     * Plain HTTP is refused, except to a loopback address: the secrets would
     * travel in clear between the slot and OpenBao. Set this only for a bench.
     */
    readonly allowInsecureHttp?: boolean;
    readonly timeoutMs?: number;
    readonly maxContentBytes?: number;
    readonly listLimit?: number;
    readonly id?: string;
    /** For tests. */
    readonly fetch?: typeof fetch;
}

interface IMetadata {
    readonly currentVersion: number;
    readonly createdTime: string;
    readonly updatedTime: string;
    readonly custom: Record<string, string>;
    /** Versions that still hold data, neither deleted nor destroyed. */
    readonly live: ReadonlySet<number>;
}

/**
 * Secrets in an OpenBao (or HashiCorp Vault) KV version 2 mount, over its
 * HTTP API.
 *
 * Each secret is one KV entry; versions are KV versions; `cas` is KV's
 * check-and-set. A `keys` secret is stored as its data, unchanged, so other
 * OpenBao tools read it natively; a file is stored as its fields plus a
 * reserved marker. Audiences and the kind live in the entry's custom
 * metadata. The token never appears in an error.
 */
export class OpenBaoVaultStore implements ISecretStore {
    readonly id: string;
    private readonly _address: string;
    private readonly _mount: string;
    private readonly _prefix: readonly string[];
    private readonly _fetch: typeof fetch;
    private readonly _timeoutMs: number;
    private readonly _maxContentBytes: number;
    private readonly _listLimit: number;

    constructor(private readonly _options: IOpenBaoVaultStoreOptions) {
        let url: URL;
        try {
            url = new URL(_options.address);
        } catch {
            throw new Error(`OpenBao address "${_options.address}" is not a URL`);
        }
        if (url.protocol !== "https:" && url.protocol !== "http:") throw new Error(`OpenBao address must be https, not ${url.protocol}`);
        if (url.protocol === "http:" && !LOOPBACK_HOSTS.has(url.hostname) && !_options.allowInsecureHttp) {
            throw new Error(`OpenBao address ${url.origin} is plain HTTP: secrets would travel in clear. Use https, or set allowInsecureHttp on a bench.`);
        }
        this._address = url.origin + url.pathname.replace(/\/+$/, "");
        this._mount = (_options.mount ?? "secret").replace(/^\/+|\/+$/g, "");
        this._prefix = _options.prefix ? parseSecretPath(_options.prefix.replace(/^\/+|\/+$/g, ""), "prefix").split("/") : [];
        this._fetch = _options.fetch ?? fetch;
        this._timeoutMs = _options.timeoutMs ?? 10_000;
        this._maxContentBytes = _options.maxContentBytes ?? 512 * 1024;
        this._listLimit = _options.listLimit ?? 1000;
        this.id = _options.id ?? `openbao:${this._mount}${this._prefix.length ? `/${this._prefix.join("/")}` : ""}`;
    }

    async getCapabilitiesAsync(): Promise<IVaultCapabilities> {
        return { backend: "openbao", versioning: true, maxContentBytes: this._maxContentBytes, listLimit: this._listLimit };
    }

    async readAsync(request: IReadSecretRequest, signal?: AbortSignal): Promise<ISecretEntry> {
        const path = parseSecretPath(request.path);
        const version = parseVersion(request.version);
        const response = await this._requestAsync("GET", "data", path, { query: version ? `version=${version}` : undefined, signal });
        const data = response.body?.data;
        const metadata = isPlainObject(data) && isPlainObject(data.metadata) ? data.metadata : undefined;
        if (response.status === 404 || !isPlainObject(data) || !isPlainObject(data.data) || !metadata || metadata.destroyed === true || (metadata.deletion_time ?? "") !== "") {
            throw version ? new VaultError("not_found", `secret "${path}" has no version ${version}`) : notFound(path);
        }
        return { path, version: Number(metadata.version), createdTime: toIsoInstant(metadata.created_time), content: decode(data.data) };
    }

    async writeAsync(request: IWriteSecretRequest, signal?: AbortSignal): Promise<IWriteSecretResult> {
        const path = parseSecretPath(request.path);
        const cas = parseCas(request.cas);
        const content = parseContent(request.content, this._maxContentBytes);
        const response = await this._requestAsync("POST", "data", path, { body: { options: cas !== undefined ? { cas } : {}, data: encode(content) }, signal });
        const version = Number((response.body?.data as { version?: unknown } | undefined)?.version);
        if (!Number.isSafeInteger(version)) throw new VaultError("store_error", `OpenBao answered the write of "${path}" without a version`);
        // The kind of the current version, for summaries; the version itself already says it.
        const metadata = await this._metadataAsync(path, signal);
        if (metadata && metadata.custom[OPENBAO_METADATA_KEYS.kind] !== content.kind) {
            await this._writeCustomAsync(path, { ...metadata.custom, [OPENBAO_METADATA_KEYS.kind]: content.kind }, signal);
        }
        return { path, version };
    }

    async listAsync(request: IListSecretsRequest, signal?: AbortSignal): Promise<IListSecretsResult> {
        const prefix = parsePrefix(request.prefix);
        const limit = parseLimit(request.limit, this._listLimit);
        const paths: string[] = [];
        if (prefix) paths.push(prefix);
        const folders = [prefix];
        while (folders.length > 0 && paths.length < MAX_WALK) {
            const folder = folders.shift()!;
            const response = await this._requestAsync("GET", "metadata", folder, { query: "list=true", signal });
            const keys = (response.body?.data as { keys?: unknown } | undefined)?.keys;
            if (response.status === 404 || !Array.isArray(keys)) continue;
            for (const key of keys) {
                if (typeof key !== "string") continue;
                const child = folder ? `${folder}/${key.replace(/\/$/, "")}` : key.replace(/\/$/, "");
                if (key.endsWith("/")) folders.push(child);
                else paths.push(child);
            }
        }
        const items: ISecretSummary[] = [];
        let truncated = false;
        for (const path of [...new Set(paths)].sort()) {
            if (!isSecretPath(path)) continue;
            const metadata = await this._metadataAsync(path, signal);
            if (!metadata) continue;
            if (items.length === limit) {
                truncated = true;
                break;
            }
            items.push(summaryOf(path, metadata));
        }
        return { items, truncated };
    }

    async describeAsync(path: SecretPath, signal?: AbortSignal): Promise<ISecretSummary> {
        const parsed = parseSecretPath(path);
        const metadata = await this._metadataAsync(parsed, signal);
        if (!metadata) throw notFound(parsed);
        return summaryOf(parsed, metadata);
    }

    async shareAsync(request: IShareSecretRequest, signal?: AbortSignal): Promise<ISecretSummary> {
        const path = parseSecretPath(request.path);
        const audiences = parseAudiences(request.audiences);
        const metadata = await this._metadataAsync(path, signal);
        if (!metadata) throw notFound(path);
        // OpenBao accepts custom metadata values of 1 to 512 characters: no audience means no key.
        const joined = audiences.join(",");
        if (joined.length > MAX_METADATA_VALUE)
            throw new VaultError("limit_exceeded", `the audiences of "${path}" take ${joined.length} characters, OpenBao keeps ${MAX_METADATA_VALUE}`);
        const { [OPENBAO_METADATA_KEYS.audiences]: _previous, ...others } = metadata.custom;
        const custom = joined ? { ...others, [OPENBAO_METADATA_KEYS.audiences]: joined } : others;
        await this._writeCustomAsync(path, custom, signal);
        return summaryOf(path, { ...metadata, custom });
    }

    async deleteAsync(request: IDeleteSecretRequest, signal?: AbortSignal): Promise<IDeleteSecretResult> {
        const path = parseSecretPath(request.path);
        const metadata = await this._metadataAsync(path, signal);
        if (!metadata) throw notFound(path);
        await this._requestAsync("DELETE", "metadata", path, { signal });
        return { path, versions: metadata.live.size };
    }

    async closeAsync(): Promise<void> {}

    /** The entry's metadata, or `undefined` when it does not exist or its current version is deleted. */
    private async _metadataAsync(path: SecretPath, signal: AbortSignal | undefined): Promise<IMetadata | undefined> {
        const response = await this._requestAsync("GET", "metadata", path, { signal });
        const data = response.body?.data;
        if (response.status === 404 || !isPlainObject(data)) return undefined;
        const live = new Set<number>();
        if (isPlainObject(data.versions)) {
            for (const [version, state] of Object.entries(data.versions)) {
                if (isPlainObject(state) && state.destroyed !== true && (state.deletion_time ?? "") === "") live.add(Number(version));
            }
        }
        const currentVersion = Number(data.current_version);
        if (!live.has(currentVersion)) return undefined;
        const custom: Record<string, string> = {};
        if (isPlainObject(data.custom_metadata)) {
            for (const [key, value] of Object.entries(data.custom_metadata)) if (typeof value === "string") custom[key] = value;
        }
        return { currentVersion, createdTime: toIsoInstant(data.created_time), updatedTime: toIsoInstant(data.updated_time), custom, live };
    }

    private async _writeCustomAsync(path: SecretPath, custom: Record<string, string>, signal: AbortSignal | undefined): Promise<void> {
        await this._requestAsync("POST", "metadata", path, { body: { custom_metadata: custom }, signal });
    }

    private async _requestAsync(
        method: "GET" | "POST" | "DELETE",
        area: "data" | "metadata",
        path: SecretPath,
        options: { query?: string; body?: unknown; signal?: AbortSignal }
    ): Promise<{ status: number; body?: Record<string, unknown> }> {
        const segments = [...this._prefix, ...(path ? path.split("/") : [])].map(encodeURIComponent);
        const url = `${this._address}/v1/${this._mount}/${area}/${segments.join("/")}${options.query ? `?${options.query}` : ""}`;
        const token = typeof this._options.token === "function" ? await this._options.token() : this._options.token;
        const timeout = AbortSignal.timeout(this._timeoutMs);
        let response: Response;
        try {
            response = await this._fetch(url, {
                method,
                headers: {
                    "x-vault-token": token,
                    ...(this._options.namespace ? { "x-vault-namespace": this._options.namespace } : {}),
                    ...(options.body !== undefined ? { "content-type": "application/json" } : {}),
                },
                ...(options.body !== undefined ? { body: JSON.stringify(options.body) } : {}),
                signal: options.signal ? AbortSignal.any([options.signal, timeout]) : timeout,
            });
        } catch (error) {
            options.signal?.throwIfAborted();
            throw new VaultError("store_unavailable", `OpenBao did not answer ${method} ${area}/${path}: ${error instanceof Error ? error.message : String(error)}`);
        }
        const text = await response.text();
        let body: Record<string, unknown> | undefined;
        try {
            const parsed = text ? JSON.parse(text) : undefined;
            body = isPlainObject(parsed) ? parsed : undefined;
        } catch {
            body = undefined;
        }
        if (response.ok || response.status === 404) return { status: response.status, body };

        const errors = Array.isArray(body?.errors) ? (body!.errors as unknown[]).filter((item): item is string => typeof item === "string") : [];
        const said = errors.join("; ") || `HTTP ${response.status}`;
        if (response.status === 400 && /check-and-set/i.test(said)) throw new VaultError("conflict", `secret "${path}" changed since the version given in cas`);
        if (response.status === 403) throw new VaultError("store_error", `OpenBao refused the slot's token on ${area}/${path}: check its policy`);
        if (response.status === 503 || response.status === 429 || response.status >= 500)
            throw new VaultError("store_unavailable", `OpenBao is unavailable (${response.status}): ${said}`);
        throw new VaultError("store_error", `OpenBao refused ${method} ${area}/${path} (${response.status}): ${said}`);
    }
}

function isSecretPath(path: string): boolean {
    try {
        parseSecretPath(path);
        return true;
    } catch {
        return false;
    }
}

function summaryOf(path: SecretPath, metadata: IMetadata): ISecretSummary {
    const audiences = (metadata.custom[OPENBAO_METADATA_KEYS.audiences] ?? "").split(",").filter(isAudience).sort();
    const kind: SecretKind = metadata.custom[OPENBAO_METADATA_KEYS.kind] === "file" ? "file" : "keys";
    return { path, kind, currentVersion: metadata.currentVersion, createdTime: metadata.createdTime, updatedTime: metadata.updatedTime, audiences: [...new Set(audiences)] };
}

function encode(content: ISecretContent): Record<string, unknown> {
    if (content.kind === "keys") return { ...content.data };
    return { [FILE_MARK]: "file", ...content.file };
}

function decode(data: Record<string, unknown>): ISecretContent {
    if (data[FILE_MARK] === "file") {
        return {
            kind: "file",
            file: {
                name: String(data.name ?? ""),
                contentType: String(data.contentType ?? "application/octet-stream"),
                encoding: data.encoding === "base64" ? "base64" : "utf8",
                content: String(data.content ?? ""),
            },
        };
    }
    return { kind: "keys", data };
}
