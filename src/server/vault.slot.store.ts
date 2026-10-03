import { VaultError } from "../contract/errors";
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
    IVaultEncryption,
    IWriteSecretRequest,
    IWriteSecretResult,
    SecretPath,
} from "../contract/vault.types";
import { ENVELOPE_ALG, VaultKeyPair, kidOf, sealJson } from "../crypto/envelope";
import type { ISealedSecretEntry } from "./vault.behavior";

/** The part of an MCP client a slot store needs. mcp-core's `McpClient` satisfies it. */
export interface ISlotClient {
    callTool(name: string, args: Record<string, unknown>): Promise<{ content?: readonly unknown[]; structuredContent?: unknown; isError?: boolean }>;
}

export interface IVaultSlotStoreOptions {
    /** This side's key pair, to open what it reads. A new one per store when omitted: nothing read outlives the process. */
    readonly keyPair?: VaultKeyPair;
    /**
     * The `kid` of the vault slot's key, from its deployment. When set, a
     * write is never sealed for any other key, whatever the slot announces:
     * a substituted key is refused with `untrusted_key`.
     */
    readonly vaultKid?: string;
}

/**
 * A vault.v1 slot, reached as an {@link ISecretStore}: how a slot reads the
 * credentials it was shared, and how its owner writes and shares them.
 *
 * Sealing happens here, at the edge: `readAsync` sends this store's public
 * key and opens the answer with its private key; `writeAsync` seals the
 * content for the vault slot's key before it leaves. In between, the broker
 * and every transport only carry ciphertext. A slot error comes back as the
 * same `VaultError` the store threw.
 */
export class VaultSlotStore implements ISecretStore {
    private readonly _keyPair: VaultKeyPair;
    private _vaultKey?: Promise<IVaultEncryption>;

    constructor(
        readonly id: string,
        private readonly _client: ISlotClient,
        private readonly _options: IVaultSlotStoreOptions = {}
    ) {
        this._keyPair = _options.keyPair ?? VaultKeyPair.generate();
    }

    /** This side's public key: what the vault seals reads for. */
    get publicKey(): string {
        return this._keyPair.publicKey;
    }

    getCapabilitiesAsync(signal?: AbortSignal): Promise<IVaultCapabilities> {
        return this._callAsync("vault.capabilities", {}, signal);
    }

    async readAsync(request: IReadSecretRequest, signal?: AbortSignal): Promise<ISecretEntry> {
        const answer = await this._callAsync<ISealedSecretEntry>("vault.read", { ...request, recipient: this._keyPair.publicKey }, signal);
        if (answer.path !== request.path || (request.version !== undefined && answer.version !== request.version)) {
            throw new VaultError("invalid_envelope", `the vault answered for another secret than "${request.path}"`);
        }
        const content = this._keyPair.openJson(answer.sealed, { purpose: "read", path: answer.path, version: answer.version }) as ISecretContent;
        return { path: answer.path, version: answer.version, createdTime: answer.createdTime, content };
    }

    async writeAsync(request: IWriteSecretRequest, signal?: AbortSignal): Promise<IWriteSecretResult> {
        const key = await this._vaultKeyAsync(signal);
        const sealed = sealJson(key.publicKey, request.content, { purpose: "write", path: request.path });
        return this._callAsync("vault.write", { path: request.path, sealed, ...(request.cas !== undefined ? { cas: request.cas } : {}) }, signal);
    }

    listAsync(request: IListSecretsRequest, signal?: AbortSignal): Promise<IListSecretsResult> {
        return this._callAsync("vault.list", request, signal);
    }

    describeAsync(path: SecretPath, signal?: AbortSignal): Promise<ISecretSummary> {
        return this._callAsync("vault.describe", { path }, signal);
    }

    shareAsync(request: IShareSecretRequest, signal?: AbortSignal): Promise<ISecretSummary> {
        return this._callAsync("vault.share", request, signal);
    }

    deleteAsync(request: IDeleteSecretRequest, signal?: AbortSignal): Promise<IDeleteSecretResult> {
        return this._callAsync("vault.delete", request, signal);
    }

    /** The client belongs to whoever connected it; closing the store does not disconnect it. */
    async closeAsync(): Promise<void> {}

    /** The slot's key, checked once: well formed, matching its own kid, and the pinned one when there is one. */
    private _vaultKeyAsync(signal: AbortSignal | undefined): Promise<IVaultEncryption> {
        this._vaultKey ??= this.getCapabilitiesAsync(signal).then((capabilities) => {
            const key = capabilities.encryption;
            if (!key || key.alg !== ENVELOPE_ALG) throw new VaultError("untrusted_key", `vault slot "${this.id}" announces no ${ENVELOPE_ALG} key`);
            let kid: string;
            try {
                kid = kidOf(key.publicKey);
            } catch {
                throw new VaultError("untrusted_key", `vault slot "${this.id}" announces a malformed key`);
            }
            if (kid !== key.kid) throw new VaultError("untrusted_key", `vault slot "${this.id}" announces a key that does not match its kid`);
            if (this._options.vaultKid !== undefined && kid !== this._options.vaultKid) {
                throw new VaultError("untrusted_key", `vault slot "${this.id}" announces key ${kid}, not the pinned ${this._options.vaultKid}`);
            }
            return key;
        });
        this._vaultKey.catch(() => (this._vaultKey = undefined));
        return this._vaultKey;
    }

    private async _callAsync<T>(tool: string, args: object, signal: AbortSignal | undefined): Promise<T> {
        signal?.throwIfAborted();
        let result: Awaited<ReturnType<ISlotClient["callTool"]>>;
        try {
            result = await this._client.callTool(tool, { ...args });
        } catch (error) {
            throw new VaultError("store_unavailable", `vault slot "${this.id}" did not answer ${tool}: ${error instanceof Error ? error.message : String(error)}`);
        }
        const payload = payloadOf(result);
        if (result.isError) {
            const body = typeof payload === "object" && payload !== null ? (payload as { error?: unknown }).error : undefined;
            throw body ? VaultError.fromBody(body) : new VaultError("store_error", `vault slot "${this.id}" failed ${tool}: ${textOf(result) ?? "no detail"}`);
        }
        if (typeof payload !== "object" || payload === null) throw new VaultError("store_error", `vault slot "${this.id}" answered ${tool} with no JSON object`);
        return payload as T;
    }
}

function textOf(result: { content?: readonly unknown[] }): string | undefined {
    const block = result.content?.find((item) => (item as { type?: unknown }).type === "text") as { text?: unknown } | undefined;
    return typeof block?.text === "string" ? block.text : undefined;
}

function payloadOf(result: { content?: readonly unknown[]; structuredContent?: unknown }): unknown {
    if (typeof result.structuredContent === "object" && result.structuredContent !== null) return result.structuredContent;
    const text = textOf(result);
    if (text === undefined) return undefined;
    try {
        return JSON.parse(text);
    } catch {
        return undefined;
    }
}
