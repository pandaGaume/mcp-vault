import {
    createCipheriv,
    createDecipheriv,
    createHash,
    createPrivateKey,
    createPublicKey,
    diffieHellman,
    generateKeyPairSync,
    hkdfSync,
    randomBytes,
    type KeyObject,
} from "node:crypto";
import { VaultError } from "../contract/errors";
import { isPlainObject } from "../contract/validation";

/**
 * Hybrid public-key encryption, in the spirit of HPKE base mode: an
 * ephemeral X25519 key agreement with the recipient's key, HKDF-SHA256, and
 * AES-256-GCM. Only the holder of the recipient's private key can open it.
 */
export const ENVELOPE_ALG = "X25519-HKDF-SHA256-A256GCM";

const SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");
const PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
const KEY_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;

/** A secret, sealed for one recipient. Every field is base64url but `alg`. */
export interface ISealedEnvelope {
    readonly alg: string;
    /** Fingerprint of the recipient's key. */
    readonly kid: string;
    /** Ephemeral public key of the sender. */
    readonly epk: string;
    readonly iv: string;
    /** Ciphertext followed by the GCM tag. */
    readonly ct: string;
}

/**
 * What an envelope is bound to, authenticated with it: an envelope sealed for
 * a read of `scada/mqtt` version 3 does not open as a write, as another path
 * or as another version.
 */
export interface IEnvelopeContext {
    readonly purpose: "read" | "write";
    readonly path: string;
    readonly version?: number;
}

function base64url(bytes: Uint8Array): string {
    return Buffer.from(bytes).toString("base64url");
}

function bytesOf(value: unknown, label: string, length?: number): Buffer {
    if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) throw new VaultError("invalid_envelope", `${label} is not base64url`);
    const bytes = Buffer.from(value, "base64url");
    if (length !== undefined && bytes.length !== length) throw new VaultError("invalid_envelope", `${label} must be ${length} bytes`);
    return bytes;
}

function publicKeyObject(raw: Buffer): KeyObject {
    return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, raw]), format: "der", type: "spki" });
}

/** The fingerprint of a raw X25519 public key: base64url SHA-256, 22 characters. */
export function kidOf(publicKey: string): string {
    const raw = bytesOf(publicKey, "public key", KEY_BYTES);
    return base64url(createHash("sha256").update(raw).digest()).slice(0, 22);
}

/** Validates a raw X25519 public key, base64url; throws `invalid_request` otherwise. */
export function parsePublicKey(value: unknown, label = "publicKey"): string {
    try {
        bytesOf(value, label, KEY_BYTES);
    } catch {
        throw new VaultError("invalid_request", `${label} must be a raw X25519 public key, 32 bytes in base64url`);
    }
    return value as string;
}

function additionalData(context: IEnvelopeContext, kid: string): Buffer {
    return Buffer.from(JSON.stringify(["mcp-vault/v1", ENVELOPE_ALG, context.purpose, context.path, context.version ?? null, kid]), "utf8");
}

function deriveKey(shared: Buffer, epk: Buffer, recipient: Buffer): Buffer {
    return Buffer.from(hkdfSync("sha256", shared, Buffer.concat([epk, recipient]), Buffer.from(`mcp-vault/v1 ${ENVELOPE_ALG}`, "utf8"), KEY_BYTES));
}

/** Seals `plaintext` for the holder of `recipientPublicKey`. */
export function seal(recipientPublicKey: string, plaintext: Uint8Array, context: IEnvelopeContext): ISealedEnvelope {
    const recipient = bytesOf(recipientPublicKey, "recipient public key", KEY_BYTES);
    const kid = kidOf(recipientPublicKey);
    const ephemeral = generateKeyPairSync("x25519");
    const epk = ephemeral.publicKey.export({ format: "der", type: "spki" }).subarray(SPKI_PREFIX.length);
    const shared = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: publicKeyObject(recipient) });
    const iv = randomBytes(IV_BYTES);
    const cipher = createCipheriv("aes-256-gcm", deriveKey(shared, epk, recipient), iv);
    cipher.setAAD(additionalData(context, kid));
    const ct = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
    return { alg: ENVELOPE_ALG, kid, epk: base64url(epk), iv: base64url(iv), ct: base64url(ct) };
}

/** Seals a JSON value. */
export function sealJson(recipientPublicKey: string, value: unknown, context: IEnvelopeContext): ISealedEnvelope {
    return seal(recipientPublicKey, Buffer.from(JSON.stringify(value), "utf8"), context);
}

/**
 * An X25519 key pair. A reader may make a new one per process: nothing it
 * reads outlives it. A vault slot keeps one, so writers can pin its `kid`.
 */
export class VaultKeyPair {
    readonly publicKey: string;
    readonly kid: string;

    private constructor(
        private readonly _private: KeyObject,
        private readonly _raw: Buffer
    ) {
        this.publicKey = base64url(_raw);
        this.kid = kidOf(this.publicKey);
    }

    static generate(): VaultKeyPair {
        const { privateKey, publicKey } = generateKeyPairSync("x25519");
        return new VaultKeyPair(privateKey, publicKey.export({ format: "der", type: "spki" }).subarray(SPKI_PREFIX.length));
    }

    /** From the 32-byte private key, base64url, as {@link exportPrivateKey} gives it. */
    static fromPrivateKey(privateKey: string): VaultKeyPair {
        const raw = bytesOf(privateKey, "private key", KEY_BYTES);
        const key = createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, raw]), format: "der", type: "pkcs8" });
        const publicRaw = createPublicKey(key).export({ format: "der", type: "spki" }).subarray(SPKI_PREFIX.length);
        return new VaultKeyPair(key, publicRaw);
    }

    /** The private key, base64url: keep it where the slot keeps its other credentials. */
    exportPrivateKey(): string {
        return base64url(this._private.export({ format: "der", type: "pkcs8" }).subarray(PKCS8_PREFIX.length));
    }

    /** What a vault slot publishes in its capabilities. */
    get encryption() {
        return { alg: ENVELOPE_ALG, publicKey: this.publicKey, kid: this.kid };
    }

    /** Opens an envelope sealed for this key in this context; `invalid_envelope` otherwise, without saying more. */
    open(envelope: unknown, context: IEnvelopeContext): Buffer {
        if (!isPlainObject(envelope)) throw new VaultError("invalid_envelope", "the envelope must be an object");
        if (envelope.alg !== ENVELOPE_ALG) throw new VaultError("invalid_envelope", `unsupported envelope algorithm, expected ${ENVELOPE_ALG}`);
        if (envelope.kid !== this.kid) throw new VaultError("invalid_envelope", "the envelope was sealed for another key", { detail: { expectedKid: this.kid } });
        const epk = bytesOf(envelope.epk, "epk", KEY_BYTES);
        const iv = bytesOf(envelope.iv, "iv", IV_BYTES);
        const ct = bytesOf(envelope.ct, "ct");
        if (ct.length < TAG_BYTES) throw new VaultError("invalid_envelope", "the ciphertext is too short");
        try {
            const shared = diffieHellman({ privateKey: this._private, publicKey: publicKeyObject(epk) });
            const decipher = createDecipheriv("aes-256-gcm", deriveKey(shared, epk, this._raw), iv);
            decipher.setAAD(additionalData(context, this.kid));
            decipher.setAuthTag(ct.subarray(ct.length - TAG_BYTES));
            return Buffer.concat([decipher.update(ct.subarray(0, ct.length - TAG_BYTES)), decipher.final()]);
        } catch {
            throw new VaultError("invalid_envelope", "the envelope does not open: altered, or bound to another context");
        }
    }

    openJson(envelope: unknown, context: IEnvelopeContext): unknown {
        const plaintext = this.open(envelope, context);
        try {
            return JSON.parse(plaintext.toString("utf8"));
        } catch {
            throw new VaultError("invalid_envelope", "the envelope does not hold JSON");
        } finally {
            plaintext.fill(0);
        }
    }
}
