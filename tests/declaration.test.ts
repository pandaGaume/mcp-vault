import { describe, expect, it } from "vitest";
import { VaultResources, buildVaultDeclaration } from "@cyanmycelium/mcp-vault";

describe("buildVaultDeclaration", () => {
    it("declares the vault domain over its namespace, and grants nothing", () => {
        expect(buildVaultDeclaration({ version: "1", namespace: "/site1/vault/", protects: ["vault-openbao"] })).toEqual({
            version: "1",
            domain: "vault",
            namespace: { resource: "/site1/vault" },
            capabilities: ["vault.read", "vault.write", "vault.share", "vault.admin"],
            protects: ["vault-openbao"],
            resultsRequired: ["vault.write", "vault.share", "vault.admin"],
        });
    });

    it("refuses an incoherent declaration locally", () => {
        expect(() => buildVaultDeclaration({ version: "", namespace: "site1", protects: ["_broker"] })).toThrow(/namespace.*version.*_broker/);
        expect(() => buildVaultDeclaration({ version: "1", namespace: "/site1/**" })).toThrow(/namespace/);
    });
});

describe("VaultResources", () => {
    it("puts secrets and audiences in two subtrees of the namespace", () => {
        const resources = new VaultResources("/site1/vault");
        expect(resources.secret("scada/mqtt")).toBe("/site1/vault/secrets/scada/mqtt");
        expect(resources.audience("mqtt")).toBe("/site1/vault/audiences/mqtt");
        expect(() => resources.secret("../escape")).toThrow();
        expect(() => resources.audience("**")).toThrow();
    });
});
