import {
    McpAdapterBase,
    McpBehavior,
    McpToolResults,
    type IMcpRequestContext,
    type McpResource,
    type McpResourceContent,
    type McpTool,
    type McpToolResult,
} from "@cyanmycelium/mcp-core";
import { AccessUnavailableError, type AccessOutcome, type IAccessCheck, type IAccessDecision, type IAccessGuard } from "@cyanmycelium/mcp-uns";
import { VaultError, type IVaultErrorBody } from "../contract/errors";
import type { ISecretStore } from "../contract/vault.store";
import type { ISecretSummary, IVaultCapabilities, SecretPath } from "../contract/vault.types";
import { parseAudiences, parseCas, parseContent, parseLimit, parsePrefix, parseSecretPath, parseVersion } from "../contract/validation";
import { ENVELOPE_ALG, VaultKeyPair, parsePublicKey, sealJson, type ISealedEnvelope } from "../crypto/envelope";
import { VAULT_CAPABILITIES, VaultResources } from "./declaration";

export const VAULT_CAPABILITIES_URI = "vault://capabilities";

export interface IVaultBehaviorOptions {
    /** The slot's key pair: writers seal to its public key. Load it from where the slot keeps its credentials, so writers can pin its `kid`. */
    readonly keyPair: VaultKeyPair;
    /** The broker resource subtree of this slot, as declared: `/site1/vault`. */
    readonly namespace: string;
}

/** What `vault.read` answers: everything in clear but the content, sealed for the caller's key. */
export interface ISealedSecretEntry {
    readonly path: SecretPath;
    readonly version: number;
    readonly createdTime: string;
    readonly sealed: ISealedEnvelope;
}

function denial(path: SecretPath, decision: IAccessDecision): VaultError {
    return new VaultError("policy_denied", `access to vault secret "${path}" was refused`, {
        ...(decision.decisionId ? { decisionId: decision.decisionId } : {}),
        detail: { reason: decision.reason },
    });
}

class VaultAdapter extends McpAdapterBase {
    private readonly _resources: VaultResources;

    constructor(
        private readonly _store: ISecretStore,
        private readonly _guard: IAccessGuard,
        private readonly _keyPair: VaultKeyPair,
        namespace: string
    ) {
        super("vault");
        this._resources = new VaultResources(namespace);
    }

    async readResourceAsync(uri: string): Promise<McpResourceContent | undefined> {
        if (uri !== VAULT_CAPABILITIES_URI) return undefined;
        return { uri, mimeType: "application/json", text: JSON.stringify(await this._capabilitiesAsync()) };
    }

    async executeToolAsync(_uri: string, toolName: string, args: Record<string, unknown>, request?: IMcpRequestContext): Promise<McpToolResult> {
        try {
            switch (toolName) {
                case "vault.capabilities":
                    return McpToolResults.json(await this._capabilitiesAsync());
                case "vault.list":
                    return McpToolResults.json(await this._listAsync(args, request));
                case "vault.describe":
                    return McpToolResults.json(await this._readableAsync(parseSecretPath(args.path), request));
                case "vault.read":
                    return McpToolResults.json(await this._readAsync(args, request));
                case "vault.write":
                    return McpToolResults.json(await this._writeAsync(args, request));
                case "vault.share":
                    return McpToolResults.json(await this._shareAsync(args, request));
                case "vault.delete":
                    return McpToolResults.json(await this._deleteAsync(args, request));
                default:
                    return McpToolResults.error(`unknown tool: ${toolName}`);
            }
        } catch (error) {
            const body: IVaultErrorBody = VaultError.toBody(error);
            return { content: [{ type: "text", text: JSON.stringify({ error: body }) }], isError: true };
        }
    }

    private async _capabilitiesAsync(): Promise<IVaultCapabilities> {
        return { ...(await this._store.getCapabilitiesAsync()), encryption: this._keyPair.encryption };
    }

    private _secretCheck(capability: string, path: SecretPath): IAccessCheck {
        return { capability, resource: `vault:${path}`, resourcePath: this._resources.secret(path) };
    }

    private _audienceCheck(capability: string, audience: string): IAccessCheck {
        return { capability, resource: `vault-audience:${audience}`, resourcePath: this._resources.audience(audience) };
    }

    private async _authorizeAsync(checks: readonly IAccessCheck[], request: IMcpRequestContext | undefined): Promise<IAccessDecision[]> {
        let answers: IAccessDecision[];
        try {
            answers = await this._guard.authorizeAsync(checks, request);
        } catch (error) {
            if (error instanceof AccessUnavailableError) throw new VaultError("authorization_unavailable", error.message);
            throw error;
        }
        return checks.map((_, index) => answers[index] ?? { allowed: false, reason: "no-decision" });
    }

    /**
     * The summary of an existing secret, once the caller has shown `capability`
     * on it. A secret that does not exist is `not_found` only to a caller who
     * would have had the right: the others cannot probe for names.
     */
    private async _existingAsync(path: SecretPath, capability: string, request: IMcpRequestContext | undefined): Promise<ISecretSummary> {
        try {
            return await this._store.describeAsync(path);
        } catch (error) {
            if (!(error instanceof VaultError) || error.code !== "not_found") throw error;
            const [decision] = await this._authorizeAsync([this._secretCheck(capability, path)], request);
            if (!decision!.allowed) throw denial(path, decision!);
            throw error;
        }
    }

    /** A secret may be read through `vault.read` on itself, or on any audience it is shared with. */
    private async _readableAsync(path: SecretPath, request: IMcpRequestContext | undefined): Promise<ISecretSummary> {
        const summary = await this._existingAsync(path, VAULT_CAPABILITIES.read, request);
        const checks = [this._secretCheck(VAULT_CAPABILITIES.read, path), ...summary.audiences.map((audience) => this._audienceCheck(VAULT_CAPABILITIES.read, audience))];
        const decisions = await this._authorizeAsync(checks, request);
        if (!decisions.some((decision) => decision.allowed)) throw denial(path, decisions[0]!);
        return summary;
    }

    /** Filtered after the fact: a secret the caller may not read is left out, as if it did not exist. */
    private async _listAsync(args: Record<string, unknown>, request: IMcpRequestContext | undefined) {
        const capabilities = await this._store.getCapabilitiesAsync();
        const result = await this._store.listAsync({ prefix: parsePrefix(args.prefix), limit: parseLimit(args.limit, capabilities.listLimit) });
        if (result.items.length === 0) return result;
        const checks: IAccessCheck[] = [];
        const owner: number[] = [];
        result.items.forEach((item, index) => {
            checks.push(this._secretCheck(VAULT_CAPABILITIES.read, item.path));
            owner.push(index);
            for (const audience of item.audiences) {
                checks.push(this._audienceCheck(VAULT_CAPABILITIES.read, audience));
                owner.push(index);
            }
        });
        const decisions = await this._authorizeAsync(checks, request);
        const readable = new Set(decisions.flatMap((decision, index) => (decision.allowed ? [owner[index]!] : [])));
        return { ...result, items: result.items.filter((_, index) => readable.has(index)) };
    }

    /** The content leaves the slot sealed for the key the caller sent: the broker, the transport and an agent's context only see ciphertext. */
    private async _readAsync(args: Record<string, unknown>, request: IMcpRequestContext | undefined): Promise<ISealedSecretEntry> {
        const path = parseSecretPath(args.path);
        const version = parseVersion(args.version);
        const recipient = parsePublicKey(args.recipient, "recipient");
        await this._readableAsync(path, request);
        const entry = await this._store.readAsync({ path, ...(version ? { version } : {}) });
        return { path, version: entry.version, createdTime: entry.createdTime, sealed: sealJson(recipient, entry.content, { purpose: "read", path, version: entry.version }) };
    }

    /** The content arrives sealed for the slot's key, bound to its path; it is opened here and nowhere before. */
    private async _writeAsync(args: Record<string, unknown>, request: IMcpRequestContext | undefined) {
        const path = parseSecretPath(args.path);
        const cas = parseCas(args.cas);
        const [decision] = await this._authorizeAsync([this._secretCheck(VAULT_CAPABILITIES.write, path)], request);
        if (!decision!.allowed) throw denial(path, decision!);
        try {
            const capabilities = await this._store.getCapabilitiesAsync();
            const content = parseContent(this._keyPair.openJson(args.sealed, { purpose: "write", path }), capabilities.maxContentBytes);
            const result = await this._store.writeAsync({ path, content, ...(cas !== undefined ? { cas } : {}) });
            this._guard.report(decision!, "success");
            return result;
        } catch (error) {
            this._guard.report(decision!, "failure", VaultError.toBody(error).code);
            throw error;
        }
    }

    /** `vault.share` on the secret, and on each audience added; removing an audience needs only the first. */
    private async _shareAsync(args: Record<string, unknown>, request: IMcpRequestContext | undefined): Promise<ISecretSummary> {
        const path = parseSecretPath(args.path);
        const audiences = parseAudiences(args.audiences);
        const summary = await this._existingAsync(path, VAULT_CAPABILITIES.share, request);
        const added = audiences.filter((audience) => !summary.audiences.includes(audience));
        const decisions = await this._authorizeAsync(
            [this._secretCheck(VAULT_CAPABILITIES.share, path), ...added.map((audience) => this._audienceCheck(VAULT_CAPABILITIES.share, audience))],
            request
        );
        const refused = decisions.find((decision) => !decision.allowed);
        if (refused) {
            this._reportAll(decisions, "refused", "policy_denied");
            const index = decisions.indexOf(refused);
            if (index === 0) throw denial(path, refused);
            throw new VaultError("policy_denied", `sharing "${path}" with audience "${added[index - 1]}" was refused`, {
                ...(refused.decisionId ? { decisionId: refused.decisionId } : {}),
                detail: { reason: refused.reason, audience: added[index - 1] },
            });
        }
        try {
            const result = await this._store.shareAsync({ path, audiences });
            this._reportAll(decisions, "success");
            return result;
        } catch (error) {
            this._reportAll(decisions, "failure", VaultError.toBody(error).code);
            throw error;
        }
    }

    private async _deleteAsync(args: Record<string, unknown>, request: IMcpRequestContext | undefined) {
        const path = parseSecretPath(args.path);
        const [decision] = await this._authorizeAsync([this._secretCheck(VAULT_CAPABILITIES.admin, path)], request);
        if (!decision!.allowed) throw denial(path, decision!);
        try {
            const result = await this._store.deleteAsync({ path });
            this._guard.report(decision!, "success");
            return result;
        } catch (error) {
            this._guard.report(decision!, "failure", VaultError.toBody(error).code);
            throw error;
        }
    }

    private _reportAll(decisions: readonly IAccessDecision[], outcome: AccessOutcome, errorCode?: string): void {
        for (const decision of decisions) if (decision.allowed) this._guard.report(decision, outcome, errorCode);
    }
}

/**
 * The MCP surface of vault.v1: publishes any {@link ISecretStore} as a slot.
 *
 * Nothing secret crosses it in clear. A reader sends its public key and gets
 * the content sealed for it; a writer seals the content for the slot's key.
 * Every operation asks the guard first; mutations report their outcome under
 * the decision that allowed them.
 */
export class VaultBehavior extends McpBehavior {
    constructor(store: ISecretStore, guard: IAccessGuard, options: IVaultBehaviorOptions) {
        super(new VaultAdapter(store, guard, options.keyPair, options.namespace), { namespace: "vault" });
    }

    protected override _buildResources(): McpResource[] {
        return [
            {
                uri: VAULT_CAPABILITIES_URI,
                name: "Vault capabilities",
                description: "vault.v1 capabilities of the store behind this slot, and the slot's public key.",
                mimeType: "application/json",
            },
        ];
    }

    protected override _buildTools(): McpTool[] {
        const path = { type: "string", description: "Secret path: segments of letters, digits, '.', '_' or '-', separated by '/'. E.g. scada/mqtt" };
        const sealed = {
            type: "object",
            description: `An envelope (${ENVELOPE_ALG}). Seal the content with the slot's public key from vault.capabilities; never send a secret in clear.`,
            properties: { alg: { type: "string" }, kid: { type: "string" }, epk: { type: "string" }, iv: { type: "string" }, ct: { type: "string" } },
            required: ["alg", "kid", "epk", "iv", "ct"],
        };
        return [
            {
                name: "vault.capabilities",
                description: "The store behind this slot (backend, versioning, size limits) and the slot's public key, to seal writes to. Pin its kid.",
                inputSchema: { type: "object", properties: {} },
            },
            {
                name: "vault.list",
                description: "List secrets under a prefix with kind, version, times and audiences; never their content. Secrets you may not read are left out.",
                inputSchema: {
                    type: "object",
                    properties: { prefix: { type: "string", description: "Subtree, matched by whole segments." }, limit: { type: "integer", minimum: 1 } },
                },
            },
            {
                name: "vault.describe",
                description: "Kind, current version, times and audiences of one secret; never its content.",
                inputSchema: { type: "object", properties: { path }, required: ["path"] },
            },
            {
                name: "vault.read",
                description:
                    "Read a secret, sealed for the recipient key you send: only the holder of the matching private key can open it. Allowed by vault.read on the secret, or on one of its audiences.",
                inputSchema: {
                    type: "object",
                    properties: {
                        path,
                        version: { type: "integer", minimum: 1, description: "The current version when omitted." },
                        recipient: { type: "string", description: "Your raw X25519 public key, base64url." },
                    },
                    required: ["path", "recipient"],
                },
            },
            {
                name: "vault.write",
                description:
                    "Write a new version of a secret: a JSON object of keys, or a configuration file. The content is sealed for the slot's key and bound to the path. Audiences are kept.",
                inputSchema: {
                    type: "object",
                    properties: { path, sealed, cas: { type: "integer", minimum: 0, description: "0: only if the secret does not exist. n: only if its current version is n." } },
                    required: ["path", "sealed"],
                },
            },
            {
                name: "vault.share",
                description:
                    "Set the complete list of audiences a secret is shared with. The broker's policy decides who belongs to each audience; you need vault.share on the secret and on every audience you add.",
                inputSchema: {
                    type: "object",
                    properties: {
                        path,
                        audiences: { type: "array", items: { type: "string" }, uniqueItems: true, description: "Lowercase names, e.g. mqtt. [] shares with nobody." },
                    },
                    required: ["path", "audiences"],
                },
            },
            {
                name: "vault.delete",
                description: "Delete a secret and every version of it, for good. Administration only; audited by the broker.",
                inputSchema: { type: "object", properties: { path }, required: ["path"] },
            },
        ];
    }
}
