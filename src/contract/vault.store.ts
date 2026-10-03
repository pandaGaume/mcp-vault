import type {
    IDeleteSecretRequest,
    IDeleteSecretResult,
    IListSecretsRequest,
    IListSecretsResult,
    IReadSecretRequest,
    ISecretEntry,
    ISecretSummary,
    IShareSecretRequest,
    IVaultCapabilities,
    IWriteSecretRequest,
    IWriteSecretResult,
    SecretPath,
} from "./vault.types";

/**
 * The vault.v1 contract, as a backend implements it.
 *
 * A store keeps plaintext: it lives inside the vault slot, next to its keys,
 * and talks to its backend over TLS. Sealing is the slot's job, not the
 * store's. Every failure is a `VaultError`.
 */
export interface ISecretStore {
    readonly id: string;
    getCapabilitiesAsync(signal?: AbortSignal): Promise<IVaultCapabilities>;
    /** Rejects with `not_found` when the secret, or that version of it, does not exist. */
    readAsync(request: IReadSecretRequest, signal?: AbortSignal): Promise<ISecretEntry>;
    /** A new version; the audiences are kept. Rejects with `conflict` when `cas` does not match. */
    writeAsync(request: IWriteSecretRequest, signal?: AbortSignal): Promise<IWriteSecretResult>;
    listAsync(request: IListSecretsRequest, signal?: AbortSignal): Promise<IListSecretsResult>;
    describeAsync(path: SecretPath, signal?: AbortSignal): Promise<ISecretSummary>;
    /** Replaces the audiences of an existing secret. */
    shareAsync(request: IShareSecretRequest, signal?: AbortSignal): Promise<ISecretSummary>;
    /** Removes every version and the audiences, for good. */
    deleteAsync(request: IDeleteSecretRequest, signal?: AbortSignal): Promise<IDeleteSecretResult>;
    closeAsync(): Promise<void>;
}
