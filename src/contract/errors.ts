export type VaultErrorCode =
    | "invalid_request"
    | "not_found"
    | "conflict"
    | "limit_exceeded"
    | "invalid_envelope"
    | "untrusted_key"
    | "policy_denied"
    | "authorization_unavailable"
    | "store_unavailable"
    | "store_error";

export const VAULT_ERROR_CODES: readonly VaultErrorCode[] = [
    "invalid_request",
    "not_found",
    "conflict",
    "limit_exceeded",
    "invalid_envelope",
    "untrusted_key",
    "policy_denied",
    "authorization_unavailable",
    "store_unavailable",
    "store_error",
];

/** The serialized form of an error, as it travels in a tool result. Never carries a secret. */
export interface IVaultErrorBody {
    readonly code: VaultErrorCode;
    readonly message: string;
    /** Broker decision that refused the request, when there was one. */
    readonly decisionId?: string;
    readonly detail?: Readonly<Record<string, unknown>>;
}

/** A normalized failure of a vault store, local or reached through a slot. */
export class VaultError extends Error implements IVaultErrorBody {
    readonly code: VaultErrorCode;
    readonly decisionId?: string;
    readonly detail?: Readonly<Record<string, unknown>>;

    constructor(code: VaultErrorCode, message: string, options: { decisionId?: string; detail?: Readonly<Record<string, unknown>> } = {}) {
        super(message);
        this.name = "VaultError";
        this.code = code;
        this.decisionId = options.decisionId;
        this.detail = options.detail;
    }

    toBody(): IVaultErrorBody {
        return {
            code: this.code,
            message: this.message,
            ...(this.decisionId ? { decisionId: this.decisionId } : {}),
            ...(this.detail ? { detail: this.detail } : {}),
        };
    }

    static toBody(error: unknown): IVaultErrorBody {
        if (error instanceof VaultError) return error.toBody();
        return { code: "store_error", message: error instanceof Error ? error.message : String(error) };
    }

    /** Rebuilds the error a slot reported, so a remote store fails like a local one. */
    static fromBody(body: unknown): VaultError {
        const candidate = (typeof body === "object" && body !== null ? body : {}) as Partial<IVaultErrorBody>;
        const code = VAULT_ERROR_CODES.includes(candidate.code as VaultErrorCode) ? (candidate.code as VaultErrorCode) : "store_error";
        const message = typeof candidate.message === "string" ? candidate.message : "the vault reported an error without a message";
        return new VaultError(code, message, {
            ...(typeof candidate.decisionId === "string" ? { decisionId: candidate.decisionId } : {}),
            ...(typeof candidate.detail === "object" && candidate.detail !== null ? { detail: candidate.detail } : {}),
        });
    }
}

export function invalid(message: string, detail?: Readonly<Record<string, unknown>>): VaultError {
    return new VaultError("invalid_request", message, detail ? { detail } : {});
}

export function notFound(path: string): VaultError {
    return new VaultError("not_found", `no secret at "${path}"`);
}
