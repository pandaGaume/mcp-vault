import { describe, expect, it } from "vitest";
import { ENVELOPE_ALG, VaultError, VaultKeyPair, kidOf, parsePublicKey, seal, sealJson } from "@cyanmycelium/mcp-vault";

const READ = { purpose: "read", path: "scada/mqtt", version: 3 } as const;

function code(action: () => unknown): string | undefined {
    try {
        action();
    } catch (error) {
        return error instanceof VaultError ? error.code : "not-a-vault-error";
    }
    return undefined;
}

describe("sealed envelopes", () => {
    it("open only with the recipient's private key, in the same context", () => {
        const reader = VaultKeyPair.generate();
        const envelope = sealJson(reader.publicKey, { password: "s3cr3t" }, READ);
        expect(envelope).toMatchObject({ alg: ENVELOPE_ALG, kid: reader.kid });
        expect(JSON.stringify(envelope)).not.toContain("s3cr3t");
        expect(reader.openJson(envelope, READ)).toEqual({ password: "s3cr3t" });
    });

    it("never repeat: two seals of the same value differ", () => {
        const reader = VaultKeyPair.generate();
        const a = sealJson(reader.publicKey, "same", READ);
        const b = sealJson(reader.publicKey, "same", READ);
        expect(a.epk).not.toBe(b.epk);
        expect(a.ct).not.toBe(b.ct);
    });

    it("refuse another key, another context, or any altered byte", () => {
        const reader = VaultKeyPair.generate();
        const envelope = sealJson(reader.publicKey, { password: "s3cr3t" }, READ);
        expect(code(() => VaultKeyPair.generate().openJson(envelope, READ))).toBe("invalid_envelope");
        expect(code(() => reader.openJson(envelope, { ...READ, path: "scada/other" }))).toBe("invalid_envelope");
        expect(code(() => reader.openJson(envelope, { ...READ, version: 2 }))).toBe("invalid_envelope");
        expect(code(() => reader.openJson(envelope, { purpose: "write", path: READ.path }))).toBe("invalid_envelope");
        const ct = Buffer.from(envelope.ct, "base64url");
        ct[0]! ^= 1;
        expect(code(() => reader.openJson({ ...envelope, ct: ct.toString("base64url") }, READ))).toBe("invalid_envelope");
        expect(code(() => reader.openJson({ ...envelope, kid: VaultKeyPair.generate().kid }, READ))).toBe("invalid_envelope");
        expect(code(() => reader.openJson({ ...envelope, alg: "none" }, READ))).toBe("invalid_envelope");
        expect(code(() => reader.openJson("not an envelope", READ))).toBe("invalid_envelope");
    });

    it("round-trip a key pair through its exported private key", () => {
        const original = VaultKeyPair.generate();
        const restored = VaultKeyPair.fromPrivateKey(original.exportPrivateKey());
        expect(restored.publicKey).toBe(original.publicKey);
        expect(restored.kid).toBe(original.kid);
        expect(restored.open(seal(original.publicKey, Buffer.from("x"), READ), READ).toString()).toBe("x");
    });

    it("fingerprint keys and validate them", () => {
        const pair = VaultKeyPair.generate();
        expect(kidOf(pair.publicKey)).toBe(pair.kid);
        expect(pair.kid).toMatch(/^[A-Za-z0-9_-]{22}$/);
        expect(parsePublicKey(pair.publicKey)).toBe(pair.publicKey);
        expect(code(() => parsePublicKey("too-short"))).toBe("invalid_request");
        expect(code(() => parsePublicKey(42))).toBe("invalid_request");
    });
});
