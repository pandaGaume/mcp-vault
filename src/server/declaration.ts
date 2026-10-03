import { isAudience, parseSecretPath } from "../contract/validation";
import type { SecretPath } from "../contract/vault.types";

export const VAULT_DOMAIN = "vault";

export const VAULT_CAPABILITIES = {
    /** Read a secret: on the secret itself, or on one of the audiences it is shared with. */
    read: "vault.read",
    /** Write a new version of a secret. */
    write: "vault.write",
    /** Share a secret: on the secret, and on every audience it is added to. */
    share: "vault.share",
    /** Delete a secret, every version. */
    admin: "vault.admin",
} as const;

/** Mutations: the broker expects their outcome, and flags a decision left without one. */
export const VAULT_RESULTS_REQUIRED = [VAULT_CAPABILITIES.write, VAULT_CAPABILITIES.share, VAULT_CAPABILITIES.admin] as const;

const RESOURCE_SEGMENT = /^[A-Za-z0-9_][A-Za-z0-9._-]*$/;

/** A broker resource path, normalized: `/site1/vault`. Throws on anything else. */
export function parseNamespace(value: string): string {
    const trimmed = typeof value === "string" ? value.replace(/\/+$/, "") : "";
    const segments = trimmed.split("/").slice(1);
    if (!trimmed.startsWith("/") || segments.length === 0 || !segments.every((segment) => RESOURCE_SEGMENT.test(segment))) {
        throw new Error(`namespace "${value}" is not a broker resource path such as /site1/vault`);
    }
    return trimmed;
}

/**
 * Where the vault's objects sit in the broker's resource space. The policy
 * sees two subtrees, and nothing else:
 *
 * - `<namespace>/secrets/<path>`: one secret, e.g. `/site1/vault/secrets/scada/mqtt`;
 * - `<namespace>/audiences/<name>`: one audience, e.g. `/site1/vault/audiences/mqtt`.
 */
export class VaultResources {
    readonly namespace: string;

    constructor(namespace: string) {
        this.namespace = parseNamespace(namespace);
    }

    secret(path: SecretPath): string {
        return `${this.namespace}/secrets/${parseSecretPath(path)}`;
    }

    audience(name: string): string {
        if (!isAudience(name)) throw new Error(`"${name}" is not an audience name`);
        return `${this.namespace}/audiences/${name}`;
    }
}

export interface IVaultDeclarationInput {
    /** Version string of this declaration; the broker echoes it back. */
    readonly version: string;
    /** Resource subtree this slot serves, e.g. `/site1/vault`; the broker refuses any check outside it. */
    readonly namespace: string;
    /** Storage slots only this slot may call; each must already be in the broker's `protectedSlots`. */
    readonly protects?: readonly string[];
}

/**
 * The `broker/authorization/declare` payload of a vault slot, shaped as
 * mcp-broker-provider's `IAuthorizationDeclaration`.
 *
 * Descriptive only: an address space, a capability vocabulary and the storage
 * slots to protect. No role, assignment or deny: the slot cannot authorize
 * itself, and no slot can grant another one access to a secret. Sharing a
 * secret with an audience is a choice of its owner; who belongs to the
 * audience is the broker's policy.
 *
 * Throws when the input is incoherent, so a bad declaration fails in the
 * deployment that wrote it rather than as a refusal from the broker.
 */
export function buildVaultDeclaration(input: IVaultDeclarationInput) {
    const problems: string[] = [];
    let namespace: string | undefined;
    try {
        namespace = parseNamespace(input.namespace);
    } catch (error) {
        problems.push((error as Error).message);
    }
    if (!input.version) problems.push("version is required");
    const protects = [...new Set(input.protects ?? [])];
    for (const slot of protects) {
        if (!slot || slot.startsWith("_")) problems.push(`slot "${slot}" cannot be protected`);
    }
    if (problems.length > 0) throw new Error(`declaration refused locally: ${problems.join("; ")}`);
    return {
        version: input.version,
        domain: VAULT_DOMAIN,
        namespace: { resource: namespace! },
        capabilities: Object.values(VAULT_CAPABILITIES),
        protects,
        resultsRequired: [...VAULT_RESULTS_REQUIRED],
    };
}
