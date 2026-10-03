/**
 * A secret's path inside the vault: `/`-separated segments of letters, digits,
 * `_`, `.` and `-`, never starting with `.`. For instance `scada/mqtt`.
 */
export type SecretPath = string;

export const SECRET_KINDS = ["keys", "file"] as const;
/** `keys`: a JSON object of named values. `file`: one configuration file. */
export type SecretKind = (typeof SECRET_KINDS)[number];

export const FILE_ENCODINGS = ["utf8", "base64"] as const;
export type FileEncoding = (typeof FILE_ENCODINGS)[number];

/** A configuration file kept as a secret: `mosquitto.conf`, a client certificate, a `.env`... */
export interface ISecretFile {
    readonly name: string;
    /** For instance `text/plain`, `application/yaml`, `application/x-pem-file`. */
    readonly contentType: string;
    /** `utf8` for text, `base64` for anything binary. */
    readonly encoding: FileEncoding;
    readonly content: string;
}

/** What a secret holds. Inside a slot, it only ever travels sealed. */
export type ISecretContent = { readonly kind: "keys"; readonly data: Readonly<Record<string, unknown>> } | { readonly kind: "file"; readonly file: ISecretFile };

/** One version of a secret. */
export interface ISecretEntry {
    readonly path: SecretPath;
    readonly version: number;
    /** When this version was written, UTC ISO 8601. */
    readonly createdTime: string;
    readonly content: ISecretContent;
}

/** What may be known about a secret without reading it. */
export interface ISecretSummary {
    readonly path: SecretPath;
    /** Kind of the current version. */
    readonly kind: SecretKind;
    readonly currentVersion: number;
    readonly createdTime: string;
    readonly updatedTime: string;
    /** Audiences the secret is shared with, sorted. The broker decides who belongs to each. */
    readonly audiences: readonly string[];
}

/** The public key of a vault slot, to seal what is written to it. */
export interface IVaultEncryption {
    readonly alg: string;
    /** Raw X25519 public key, base64url. */
    readonly publicKey: string;
    /** Fingerprint of the key: pin it to refuse any other. */
    readonly kid: string;
}

export interface IVaultCapabilities {
    /** `memory`, `openbao`... */
    readonly backend: string;
    /** Whether older versions stay readable after a write. */
    readonly versioning: boolean;
    /** Largest content accepted, measured as its JSON in UTF-8. */
    readonly maxContentBytes: number;
    /** Largest page `list` returns. */
    readonly listLimit: number;
    /** Present on a slot: where to seal writes to. */
    readonly encryption?: IVaultEncryption;
}

export interface IReadSecretRequest {
    readonly path: SecretPath;
    /** The current version when omitted. */
    readonly version?: number;
}

export interface IWriteSecretRequest {
    readonly path: SecretPath;
    readonly content: ISecretContent;
    /** Check-and-set: `0` writes only if the secret does not exist, `n` only if its current version is `n`. */
    readonly cas?: number;
}

export interface IWriteSecretResult {
    readonly path: SecretPath;
    readonly version: number;
}

export interface IListSecretsRequest {
    /** A subtree, matched by whole segments: `scada` matches `scada/mqtt`, not `scadax`. Everything when omitted. */
    readonly prefix?: SecretPath;
    readonly limit?: number;
}

export interface IListSecretsResult {
    /** Sorted by path. */
    readonly items: readonly ISecretSummary[];
    /** True when more secrets matched than `limit`. */
    readonly truncated: boolean;
}

export interface IShareSecretRequest {
    readonly path: SecretPath;
    /** The complete set of audiences; `[]` shares with nobody. */
    readonly audiences: readonly string[];
}

export interface IDeleteSecretRequest {
    readonly path: SecretPath;
}

export interface IDeleteSecretResult {
    readonly path: SecretPath;
    /** Number of versions removed. */
    readonly versions: number;
}
