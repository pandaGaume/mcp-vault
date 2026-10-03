import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { startTestBroker, type ITestBroker } from "@cyanmycelium/mcp-broker/testing";
import { DirectTransport } from "@cyanmycelium/mcp-broker-provider";
import { McpClient, McpServerBuilder, type IMcpServer } from "@cyanmycelium/mcp-core";
import { StreamableHttpTransport } from "@cyanmycelium/mcp-core/node";
import { BrokerAccessGuard } from "@cyanmycelium/mcp-uns";
import { MemoryVaultStore, VaultBehavior, VaultKeyPair, VaultSlotStore, buildVaultDeclaration, type ISecretContent } from "@cyanmycelium/mcp-vault";

const MQTT: ISecretContent = { kind: "keys", data: { host: "mqtt.site1.local", port: 8883, username: "uns", password: "canary-5d1e-mqtt-password" } };

/**
 * The vault slot behind a real broker. scada owns `scada/**` and may publish
 * to the `mqtt` audience; the broker's policy says the MQTT slots belong to
 * that audience. scada shares its MQTT credentials with `mqtt`, and the MQTT
 * slots can read them; nobody else can. The slot decides nothing, and the
 * broker only ever sees ciphertext.
 */
describe("vault slot under broker policy", () => {
    let broker: ITestBroker;
    let server: IMcpServer;
    const vaultKey = VaultKeyPair.generate();
    const clients: McpClient[] = [];
    const wire: string[] = [];

    async function as(caller: string, options: { vaultKid?: string } = {}): Promise<VaultSlotStore> {
        const client = new McpClient({ name: caller, version: "0.1.0" }, new StreamableHttpTransport(broker.mcpUrl("vault"), { headers: broker.bearer(caller) }), 5_000);
        await client.connect();
        clients.push(client);
        const recording = {
            async callTool(name: string, args: Record<string, unknown>) {
                wire.push(JSON.stringify(args));
                const result = await client.callTool(name, args);
                wire.push(JSON.stringify(result));
                return result;
            },
        };
        return new VaultSlotStore("vault", recording, { vaultKid: options.vaultKid ?? vaultKey.kid });
    }

    beforeAll(async () => {
        broker = await startTestBroker({
            callers: {
                scada: { service: "mcp-scada" },
                uns: { service: "mcp-uns", groups: ["mqtt-clients"] },
                modbus: { service: "mcp-modbus", groups: ["mqtt-clients"] },
                historian: { service: "mcp-history" },
                admin: { groups: ["vault-admins"] },
            },
            providers: { "mcp-vault": { subjects: ["service:mcp-vault"], allowedResources: ["/site1/vault/**"] } },
            policy: {
                slotResources: { vault: "/site1/vault" },
                roles: {
                    caller: { capabilities: ["mcp.tools.call", "mcp.tools.list"] },
                    owner: { capabilities: ["vault.read", "vault.write", "vault.share"] },
                    publisher: { capabilities: ["vault.share"] },
                    reader: { capabilities: ["vault.read"] },
                    administrator: { capabilities: ["vault.admin"] },
                },
                assignments: [
                    { id: "scada-slot", subject: "service:mcp-scada", role: "caller", resource: "/site1/vault" },
                    { id: "scada-owns-its-secrets", subject: "service:mcp-scada", role: "owner", resource: "/site1/vault/secrets/scada/**" },
                    { id: "scada-publishes-to-mqtt", subject: "service:mcp-scada", role: "publisher", resource: "/site1/vault/audiences/mqtt" },
                    { id: "mqtt-slot", subject: "group:mqtt-clients", role: "caller", resource: "/site1/vault" },
                    { id: "mqtt-audience", subject: "group:mqtt-clients", role: "reader", resource: "/site1/vault/audiences/mqtt" },
                    { id: "historian-slot", subject: "service:mcp-history", role: "caller", resource: "/site1/vault" },
                    { id: "admins-slot", subject: "group:vault-admins", role: "caller", resource: "/site1/vault" },
                    { id: "admins-site", subject: "group:vault-admins", role: "administrator", resource: "/site1/vault/**" },
                ],
            },
        });

        const transport = new DirectTransport(broker.providerUrl("vault"), { secret: broker.providerSecret("mcp-vault") });
        server = new McpServerBuilder()
            .withName("vault")
            .withTransport(transport)
            .register(new VaultBehavior(new MemoryVaultStore(), new BrokerAccessGuard(transport.broker), { keyPair: vaultKey, namespace: "/site1/vault" }))
            .build();
        await server.start();
        const accepted = await transport.broker.declare(buildVaultDeclaration({ version: "1", namespace: "/site1/vault" }));
        expect(accepted.accepted).toBe(true);
    });

    afterAll(async () => {
        for (const client of clients) client.disconnect();
        await server?.stop?.();
        await broker?.stop();
    });

    it("lets scada write its MQTT credentials, sealed for the pinned vault key", async () => {
        const scada = await as("scada");
        expect(await scada.writeAsync({ path: "scada/mqtt", content: MQTT, cas: 0 })).toEqual({ path: "scada/mqtt", version: 1 });
        expect((await scada.readAsync({ path: "scada/mqtt" })).content).toEqual(MQTT);
    });

    it("keeps the secret from the MQTT slots until scada shares it", async () => {
        const uns = await as("uns");
        await expect(uns.readAsync({ path: "scada/mqtt" })).rejects.toMatchObject({ code: "policy_denied", decisionId: expect.any(String) });
        expect((await uns.listAsync({})).items).toEqual([]);
    });

    it("shares with the mqtt audience, and every MQTT slot can read", async () => {
        const scada = await as("scada");
        expect((await scada.shareAsync({ path: "scada/mqtt", audiences: ["mqtt"] })).audiences).toEqual(["mqtt"]);
        for (const caller of ["uns", "modbus"]) {
            const client = await as(caller);
            expect((await client.readAsync({ path: "scada/mqtt" })).content).toEqual(MQTT);
            expect((await client.listAsync({ prefix: "scada" })).items.map((item) => item.path)).toEqual(["scada/mqtt"]);
        }
    });

    it("refuses whoever is not in the audience, without telling whether the secret exists", async () => {
        const historian = await as("historian");
        await expect(historian.readAsync({ path: "scada/mqtt" })).rejects.toMatchObject({ code: "policy_denied" });
        await expect(historian.readAsync({ path: "scada/nothing-here" })).rejects.toMatchObject({ code: "policy_denied" });
        await expect(historian.describeAsync("scada/mqtt")).rejects.toMatchObject({ code: "policy_denied" });
    });

    it("lets a reader neither write, nor share, nor delete", async () => {
        const uns = await as("uns");
        await expect(uns.writeAsync({ path: "scada/mqtt", content: MQTT })).rejects.toMatchObject({ code: "policy_denied" });
        await expect(uns.shareAsync({ path: "scada/mqtt", audiences: ["mqtt", "everyone"] })).rejects.toMatchObject({ code: "policy_denied" });
        await expect(uns.deleteAsync({ path: "scada/mqtt" })).rejects.toMatchObject({ code: "policy_denied" });
    });

    it("keeps scada from sharing with an audience it may not publish to", async () => {
        const scada = await as("scada");
        await expect(scada.shareAsync({ path: "scada/mqtt", audiences: ["mqtt", "historians"] })).rejects.toMatchObject({
            code: "policy_denied",
            detail: expect.objectContaining({ audience: "historians" }),
        });
        expect((await scada.describeAsync("scada/mqtt")).audiences).toEqual(["mqtt"]);
    });

    it("keeps scada out of the secrets of others", async () => {
        const scada = await as("scada");
        await expect(scada.writeAsync({ path: "opcua/server", content: MQTT })).rejects.toMatchObject({ code: "policy_denied" });
    });

    it("refuses to seal for a vault key other than the pinned one", async () => {
        const scada = await as("scada", { vaultKid: VaultKeyPair.generate().kid });
        await expect(scada.writeAsync({ path: "scada/mqtt", content: MQTT })).rejects.toMatchObject({ code: "untrusted_key" });
    });

    it("rotates: a new version reaches the audience, and revoking the audience cuts it off", async () => {
        const scada = await as("scada");
        const rotated: ISecretContent = { kind: "keys", data: { ...(MQTT as { data: object }).data, password: "canary-5d1e-rotated" } };
        expect(await scada.writeAsync({ path: "scada/mqtt", content: rotated, cas: 1 })).toEqual({ path: "scada/mqtt", version: 2 });
        const modbus = await as("modbus");
        expect((await modbus.readAsync({ path: "scada/mqtt" })).content).toEqual(rotated);
        await scada.shareAsync({ path: "scada/mqtt", audiences: [] });
        await expect(modbus.readAsync({ path: "scada/mqtt" })).rejects.toMatchObject({ code: "policy_denied" });
    });

    it("keeps deletion for vault.admin", async () => {
        const admin = await as("admin");
        expect(await admin.deleteAsync({ path: "scada/mqtt" })).toEqual({ path: "scada/mqtt", versions: 2 });
    });

    it("never let a secret cross the broker in clear", () => {
        expect(wire.length).toBeGreaterThan(20);
        for (const message of wire) expect(message).not.toMatch(/canary-5d1e/);
    });
});
