import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { LoopbackTransport, McpClient, McpServerBuilder } from "@cyanmycelium/mcp-core";
import { openGuard } from "@cyanmycelium/mcp-uns";
import { MemoryVaultStore, OpenBaoVaultStore, VaultBehavior, VaultError, VaultKeyPair, VaultSlotStore, type ISecretStore } from "@cyanmycelium/mcp-vault";
import { describeVaultStoreConformance } from "@cyanmycelium/mcp-vault/conformance";
import { startFakeOpenBao, type IFakeOpenBao } from "./fake.openbao";

const TOKEN = "fake-root-token";

describeVaultStoreConformance("MemoryVaultStore", () => new MemoryVaultStore());

/** A store published by VaultBehavior, reached back through MCP: the sealed form of the contract must agree with the plain one. */
async function throughSlot(store: ISecretStore, wire?: string[]): Promise<ISecretStore> {
    const [serverEnd, clientEnd] = LoopbackTransport.createPair();
    const server = new McpServerBuilder()
        .withName("vault")
        .withTransport(serverEnd)
        .register(new VaultBehavior(store, openGuard(), { keyPair: VaultKeyPair.generate(), namespace: "/site1/vault" }))
        .build();
    await server.start();
    const client = new McpClient({ name: "conformance", version: "0.1.0" }, clientEnd, 5_000);
    await client.connect();
    // Records every argument and result that crosses MCP, as a broker would see them.
    const recording = {
        async callTool(name: string, args: Record<string, unknown>) {
            wire?.push(JSON.stringify(args));
            const result = await client.callTool(name, args);
            wire?.push(JSON.stringify(result));
            return result;
        },
    };
    const remote = new VaultSlotStore("vault", recording);
    return {
        id: remote.id,
        getCapabilitiesAsync: (signal) => remote.getCapabilitiesAsync(signal),
        readAsync: (request, signal) => remote.readAsync(request, signal),
        writeAsync: (request, signal) => remote.writeAsync(request, signal),
        listAsync: (request, signal) => remote.listAsync(request, signal),
        describeAsync: (path, signal) => remote.describeAsync(path, signal),
        shareAsync: (request, signal) => remote.shareAsync(request, signal),
        deleteAsync: (request, signal) => remote.deleteAsync(request, signal),
        async closeAsync() {
            client.disconnect();
            await store.closeAsync();
        },
    };
}

describeVaultStoreConformance("MemoryVaultStore through a vault slot", () => throughSlot(new MemoryVaultStore()));

describe("OpenBaoVaultStore, against a fake KV v2", () => {
    let bao: IFakeOpenBao;

    beforeAll(async () => {
        bao = await startFakeOpenBao(TOKEN);
    });

    afterAll(async () => {
        await bao.stop();
    });

    describeVaultStoreConformance("OpenBaoVaultStore", () => new OpenBaoVaultStore({ address: bao.address, token: TOKEN }), { cleanupAsync: async () => bao.clear() });
    describeVaultStoreConformance("OpenBaoVaultStore under a prefix", () => new OpenBaoVaultStore({ address: bao.address, token: () => TOKEN, prefix: "mcp-vault/site1" }), {
        cleanupAsync: async () => bao.clear(),
    });
    describeVaultStoreConformance("OpenBaoVaultStore through a vault slot", () => throughSlot(new OpenBaoVaultStore({ address: bao.address, token: TOKEN })), {
        cleanupAsync: async () => bao.clear(),
    });

    it("stores keys natively and files with a marker, kind and audiences in custom metadata", async () => {
        const store = new OpenBaoVaultStore({ address: bao.address, token: TOKEN });
        await store.writeAsync({ path: "scada/mqtt", content: { kind: "keys", data: { username: "scada", password: "pw" } } });
        await store.shareAsync({ path: "scada/mqtt", audiences: ["mqtt"] });
        await store.writeAsync({ path: "scada/conf", content: { kind: "file", file: { name: "a.conf", contentType: "text/plain", encoding: "utf8", content: "x" } } });
        expect(bao.bodies.map((body) => JSON.parse(body))).toEqual(
            expect.arrayContaining([
                { options: {}, data: { username: "scada", password: "pw" } },
                { custom_metadata: { "mcp-vault.kind": "keys", "mcp-vault.audiences": "mqtt" } },
                { options: {}, data: { "@mcp-vault/kind": "file", name: "a.conf", contentType: "text/plain", encoding: "utf8", content: "x" } },
            ])
        );
        bao.clear();
    });

    it("treats a soft-deleted current version as absent", async () => {
        const store = new OpenBaoVaultStore({ address: bao.address, token: TOKEN });
        await store.writeAsync({ path: "scada/mqtt", content: { kind: "keys", data: { a: 1 } } });
        bao.softDelete("scada/mqtt");
        await expect(store.readAsync({ path: "scada/mqtt" })).rejects.toMatchObject({ code: "not_found" });
        expect((await store.listAsync({})).items).toEqual([]);
        bao.clear();
    });

    it("reports a refused token without repeating it", async () => {
        const store = new OpenBaoVaultStore({ address: bao.address, token: "wrong-token-value" });
        const error = await store.readAsync({ path: "scada/mqtt" }).catch((caught: unknown) => caught);
        expect(error).toBeInstanceOf(VaultError);
        expect((error as VaultError).code).toBe("store_error");
        expect((error as VaultError).message).not.toContain("wrong-token-value");
    });

    it("reports an unreachable OpenBao as store_unavailable", async () => {
        const store = new OpenBaoVaultStore({ address: "http://127.0.0.1:9", token: TOKEN, timeoutMs: 2_000 });
        await expect(store.readAsync({ path: "scada/mqtt" })).rejects.toMatchObject({ code: "store_unavailable" });
    });
});

describe("OpenBaoVaultStore transport", () => {
    it("refuses plain HTTP to anything but loopback", () => {
        expect(() => new OpenBaoVaultStore({ address: "http://bao.site1.local:8200", token: TOKEN })).toThrow(/plain HTTP/);
        expect(() => new OpenBaoVaultStore({ address: "http://bao.site1.local:8200", token: TOKEN, allowInsecureHttp: true })).not.toThrow();
        expect(() => new OpenBaoVaultStore({ address: "https://bao.site1.local:8200", token: TOKEN })).not.toThrow();
        expect(() => new OpenBaoVaultStore({ address: "http://localhost:8200", token: TOKEN })).not.toThrow();
        expect(() => new OpenBaoVaultStore({ address: "ftp://bao", token: TOKEN })).toThrow(/https/);
    });
});

describe("what crosses MCP", () => {
    it("never carries a secret in clear, either way", async () => {
        const wire: string[] = [];
        const canary = "canary-7f3a9c1e-never-on-the-wire";
        const store = await throughSlot(new MemoryVaultStore(), wire);
        await store.writeAsync({ path: "scada/mqtt", content: { kind: "keys", data: { password: canary } } });
        await store.writeAsync({ path: "scada/conf", content: { kind: "file", file: { name: "secret.conf", contentType: "text/plain", encoding: "utf8", content: canary } } });
        expect((await store.readAsync({ path: "scada/mqtt" })).content).toEqual({ kind: "keys", data: { password: canary } });
        expect((await store.readAsync({ path: "scada/conf" })).content).toMatchObject({ kind: "file", file: { content: canary } });
        expect(wire.length).toBeGreaterThan(4);
        for (const message of wire) {
            expect(message).not.toContain(canary);
            expect(message).not.toContain("secret.conf");
        }
        await store.closeAsync();
    });
});
