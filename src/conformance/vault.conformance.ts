import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { VaultError, type VaultErrorCode } from "../contract/errors";
import type { ISecretStore } from "../contract/vault.store";
import type { ISecretContent } from "../contract/vault.types";

export interface IVaultConformanceOptions {
    /** Called after each test, after `closeAsync`: empty a mount, drop a container... */
    readonly cleanupAsync?: () => Promise<void>;
}

const MQTT = { kind: "keys", data: { host: "mqtt.site1.local", port: 8883, username: "scada", password: "s3cr3t-π" } } as const satisfies ISecretContent;
const CONF: ISecretContent = {
    kind: "file",
    file: { name: "mosquitto.conf", contentType: "text/plain", encoding: "utf8", content: "listener 8883\nrequire_certificate true\n" },
};
const CERT: ISecretContent = { kind: "file", file: { name: "client.p12", contentType: "application/x-pkcs12", encoding: "base64", content: "AAECAwQFBgc=" } };

async function failure(promise: Promise<unknown>, code: VaultErrorCode): Promise<VaultError> {
    try {
        await promise;
    } catch (error) {
        expect(error).toBeInstanceOf(VaultError);
        expect((error as VaultError).code).toBe(code);
        return error as VaultError;
    }
    throw new Error(`expected the call to reject with ${code}`);
}

/**
 * The vault.v1 conformance suite: what every store must do, whatever it
 * stores in. A store passes it directly, and again through a slot
 * (`VaultBehavior` + `VaultSlotStore`), which proves that the sealed MCP form
 * of the contract says the same thing as the TypeScript one.
 *
 * Each test starts from an empty store.
 */
export function describeVaultStoreConformance(name: string, create: () => ISecretStore | Promise<ISecretStore>, options: IVaultConformanceOptions = {}): void {
    describe(`vault.v1 conformance: ${name}`, () => {
        let store: ISecretStore;

        beforeEach(async () => {
            store = await create();
        });

        afterEach(async () => {
            await store.closeAsync();
            await options.cleanupAsync?.();
        });

        it("states its capabilities", async () => {
            const capabilities = await store.getCapabilitiesAsync();
            expect(typeof capabilities.backend).toBe("string");
            expect(typeof capabilities.versioning).toBe("boolean");
            expect(capabilities.maxContentBytes).toBeGreaterThan(1024);
            expect(capabilities.listLimit).toBeGreaterThanOrEqual(1);
        });

        it("reads back what it wrote, keys and files alike", async () => {
            expect(await store.writeAsync({ path: "scada/mqtt", content: MQTT })).toEqual({ path: "scada/mqtt", version: 1 });
            await store.writeAsync({ path: "scada/mosquitto", content: CONF });
            await store.writeAsync({ path: "scada/cert", content: CERT });

            const read = await store.readAsync({ path: "scada/mqtt" });
            expect(read).toMatchObject({ path: "scada/mqtt", version: 1, content: MQTT });
            expect(read.createdTime).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
            expect((await store.readAsync({ path: "scada/mosquitto" })).content).toEqual(CONF);
            expect((await store.readAsync({ path: "scada/cert" })).content).toEqual(CERT);
        });

        it("versions every write and keeps older versions readable", async () => {
            await store.writeAsync({ path: "scada/mqtt", content: MQTT });
            const second: ISecretContent = { kind: "keys", data: { ...MQTT.data, password: "rotated" } };
            expect(await store.writeAsync({ path: "scada/mqtt", content: second })).toEqual({ path: "scada/mqtt", version: 2 });
            expect((await store.readAsync({ path: "scada/mqtt" })).content).toEqual(second);
            const capabilities = await store.getCapabilitiesAsync();
            if (capabilities.versioning) expect((await store.readAsync({ path: "scada/mqtt", version: 1 })).content).toEqual(MQTT);
            expect((await store.describeAsync("scada/mqtt")).currentVersion).toBe(2);
        });

        it("lets a version change kind", async () => {
            await store.writeAsync({ path: "scada/mqtt", content: MQTT });
            await store.writeAsync({ path: "scada/mqtt", content: CONF });
            expect((await store.describeAsync("scada/mqtt")).kind).toBe("file");
            expect((await store.readAsync({ path: "scada/mqtt" })).content).toEqual(CONF);
        });

        it("applies check-and-set", async () => {
            expect(await store.writeAsync({ path: "scada/mqtt", content: MQTT, cas: 0 })).toEqual({ path: "scada/mqtt", version: 1 });
            await failure(store.writeAsync({ path: "scada/mqtt", content: MQTT, cas: 0 }), "conflict");
            await failure(store.writeAsync({ path: "scada/mqtt", content: MQTT, cas: 2 }), "conflict");
            expect(await store.writeAsync({ path: "scada/mqtt", content: MQTT, cas: 1 })).toEqual({ path: "scada/mqtt", version: 2 });
        });

        it("answers not_found for a missing secret or version", async () => {
            await failure(store.readAsync({ path: "nobody/here" }), "not_found");
            await failure(store.describeAsync("nobody/here"), "not_found");
            await store.writeAsync({ path: "scada/mqtt", content: MQTT });
            await failure(store.readAsync({ path: "scada/mqtt", version: 7 }), "not_found");
        });

        it("lists a subtree by whole segments, sorted, without content", async () => {
            for (const path of ["scada/mqtt", "scada/opcua/server", "scadax/other", "uns/broker", "scada"]) await store.writeAsync({ path, content: MQTT });
            const listed = await store.listAsync({ prefix: "scada" });
            expect(listed.items.map((item) => item.path)).toEqual(["scada", "scada/mqtt", "scada/opcua/server"]);
            expect(listed.truncated).toBe(false);
            expect(listed.items[1]).toEqual({
                path: "scada/mqtt",
                kind: "keys",
                currentVersion: 1,
                createdTime: expect.any(String),
                updatedTime: expect.any(String),
                audiences: [],
            });
            expect((await store.listAsync({})).items).toHaveLength(5);
            const page = await store.listAsync({ prefix: "scada", limit: 2 });
            expect(page.items.map((item) => item.path)).toEqual(["scada", "scada/mqtt"]);
            expect(page.truncated).toBe(true);
            expect((await store.listAsync({ prefix: "nothing" })).items).toEqual([]);
        });

        it("shares with a sorted set of audiences, kept across writes", async () => {
            await store.writeAsync({ path: "scada/mqtt", content: MQTT });
            expect((await store.shareAsync({ path: "scada/mqtt", audiences: ["mqtt", "historians", "mqtt"] })).audiences).toEqual(["historians", "mqtt"]);
            await store.writeAsync({ path: "scada/mqtt", content: MQTT });
            expect((await store.describeAsync("scada/mqtt")).audiences).toEqual(["historians", "mqtt"]);
            expect((await store.listAsync({ prefix: "scada" })).items[0]!.audiences).toEqual(["historians", "mqtt"]);
            expect((await store.shareAsync({ path: "scada/mqtt", audiences: [] })).audiences).toEqual([]);
            await failure(store.shareAsync({ path: "nobody/here", audiences: ["mqtt"] }), "not_found");
            await failure(store.shareAsync({ path: "scada/mqtt", audiences: ["MQTT clients"] }), "invalid_request");
        });

        it("deletes every version, for good", async () => {
            await store.writeAsync({ path: "scada/mqtt", content: MQTT });
            await store.writeAsync({ path: "scada/mqtt", content: MQTT });
            await store.shareAsync({ path: "scada/mqtt", audiences: ["mqtt"] });
            expect(await store.deleteAsync({ path: "scada/mqtt" })).toEqual({ path: "scada/mqtt", versions: 2 });
            await failure(store.readAsync({ path: "scada/mqtt" }), "not_found");
            await failure(store.deleteAsync({ path: "scada/mqtt" }), "not_found");
            await store.writeAsync({ path: "scada/mqtt", content: MQTT });
            expect(await store.describeAsync("scada/mqtt")).toMatchObject({ currentVersion: 1, audiences: [] });
        });

        it("refuses malformed paths", async () => {
            for (const path of ["", "/scada/mqtt", "scada//mqtt", "scada/../root", ".hidden", "scada/mqtt/", "a b"]) {
                await failure(store.writeAsync({ path, content: MQTT }), "invalid_request");
                await failure(store.readAsync({ path }), "invalid_request");
            }
        });

        it("refuses malformed content", async () => {
            const bad = [
                { kind: "keys", data: ["not", "an", "object"] },
                { kind: "keys", data: { "@mcp-vault/kind": "file" } },
                { kind: "file", file: { name: "", contentType: "text/plain", encoding: "utf8", content: "" } },
                { kind: "file", file: { name: "a.bin", contentType: "application/octet-stream", encoding: "base64", content: "not base64!" } },
                { kind: "file", file: { name: "a.txt", contentType: "text/plain", encoding: "latin1", content: "x" } },
                { kind: "blob", data: {} },
            ];
            for (const content of bad) await failure(store.writeAsync({ path: "scada/bad", content: content as unknown as ISecretContent }), "invalid_request");
            await failure(store.readAsync({ path: "scada/bad" }), "not_found");
        });

        it("refuses content larger than it accepts", async () => {
            const { maxContentBytes } = await store.getCapabilitiesAsync();
            const big: ISecretContent = { kind: "file", file: { name: "big.txt", contentType: "text/plain", encoding: "utf8", content: "x".repeat(maxContentBytes + 1) } };
            await failure(store.writeAsync({ path: "scada/big", content: big }), "limit_exceeded");
        });
    });
}
