<p align="center">
  <img src="https://raw.githubusercontent.com/pandaGaume/mcp-vault/main/docs/assets/logo.png" alt="mcp-vault logo: the network-discovery panda holding a bitten bao, a padlock glowing on its chest" width="180">
</p>

# mcp-vault

A vault slot for an [mcp-broker](https://github.com/pandaGaume/mcp-broker): one place where slots share keys and configuration files, stored in [OpenBao](https://openbao.org/), **sealed end to end**, with access decided by the broker.

```text
scada ──seal(vault key)──> mcp-broker ──> slot "vault" (VaultBehavior) ──TLS──> OpenBao KV v2
uns   <──open(own key)──── mcp-broker <── content sealed for the reader's key
                              │
                              └── broker/authorize: vault.read on the secret, or on one of its audiences
```

The scada slot writes the MQTT credentials, then shares them with the audience `mqtt`. The broker's policy says who is in `mqtt`: every slot that publishes or listens on MQTT. Those slots read the credentials; nobody else can, and **no secret ever crosses the broker in clear**.

Design and decisions: [docs/brief_vault_slot.md](https://github.com/pandaGaume/mcp-vault/blob/main/docs/brief_vault_slot.md) (French).

## End to end

Every secret is sealed by whoever holds it, for whoever is meant to open it. In between, only ciphertext travels: through the broker, through MCP transports, through logs and through an agent's context.

| leg | protection |
|---|---|
| writer → vault slot | the writer seals the content for the slot's X25519 public key, bound to the path; it pins the slot's `kid`, so a substituted key is refused |
| vault slot → reader | the reader sends its public key with `vault.read`; the slot seals the content for it, bound to path and version |
| vault slot ↔ OpenBao | HTTPS; plain HTTP is refused except to loopback |
| OpenBao at rest | OpenBao's barrier encryption |

Envelopes are `X25519-HKDF-SHA256-A256GCM`: an ephemeral key agreement per message, HKDF-SHA256, AES-256-GCM with the context as associated data. An envelope sealed for a read of `scada/mqtt` version 3 does not open as a write, as another path or as another version. `node:crypto` only, no dependency.

`VaultSlotStore` does all of it at the edge: a slot reads and writes plain `ISecretContent`, and seals and opens on its own side.

## Sharing: audiences

A slot cannot grant anything: the broker's policy is the only authority, and it is written by whoever runs the broker. Sharing is therefore split in two:

- **the owner** of a secret chooses which audiences it is shared with (`vault.share`);
- **the policy** says who belongs to each audience (`vault.read` on `<namespace>/audiences/<name>`).

To share with an audience, the owner needs `vault.share` on the secret **and** on the audience: the policy also says who may publish to `mqtt`. A secret is readable with `vault.read` on itself, or on any of its audiences.

```jsonc
{
    "auth": {
        "slotResources": { "vault": "/site1/vault" },
        "roles": {
            "caller": { "capabilities": ["mcp.tools.call", "mcp.tools.list"] },
            "owner": { "capabilities": ["vault.read", "vault.write", "vault.share"] },
            "publisher": { "capabilities": ["vault.share"] },
            "reader": { "capabilities": ["vault.read"] }
        },
        "assignments": [
            { "id": "scada-slot", "subject": "service:mcp-scada", "role": "caller", "resource": "/site1/vault" },
            { "id": "scada-owns", "subject": "service:mcp-scada", "role": "owner", "resource": "/site1/vault/secrets/scada/**" },
            { "id": "scada-to-mqtt", "subject": "service:mcp-scada", "role": "publisher", "resource": "/site1/vault/audiences/mqtt" },
            { "id": "mqtt-slot", "subject": "group:mqtt-clients", "role": "caller", "resource": "/site1/vault" },
            { "id": "mqtt-audience", "subject": "group:mqtt-clients", "role": "reader", "resource": "/site1/vault/audiences/mqtt" }
        ]
    }
}
```

## Use

The vault slot:

```ts
import { DirectTransport } from "@cyanmycelium/mcp-broker-provider";
import { McpServerBuilder } from "@cyanmycelium/mcp-core";
import { BrokerAccessGuard } from "@cyanmycelium/mcp-uns";
import { OpenBaoVaultStore, VaultBehavior, VaultKeyPair, buildVaultDeclaration } from "@cyanmycelium/mcp-vault";

const keyPair = VaultKeyPair.fromPrivateKey(process.env.MCP_VAULT_PRIVATE_KEY!); // VaultKeyPair.generate().exportPrivateKey(), once
const store = new OpenBaoVaultStore({ address: "https://bao.site1.local:8200", token: process.env.BAO_TOKEN!, prefix: "mcp-vault/site1" });

const transport = new DirectTransport("wss://broker.site1.local/provider/vault", { secret });
const server = new McpServerBuilder()
    .withName("vault")
    .withTransport(transport)
    .register(new VaultBehavior(store, new BrokerAccessGuard(transport.broker), { keyPair, namespace: "/site1/vault" }))
    .build();
await server.start();
await transport.broker.declare(buildVaultDeclaration({ version: "1", namespace: "/site1/vault" }));
console.log(`vault key: ${keyPair.kid}`); // give this kid to the writers
```

The scada slot, owner of the MQTT credentials:

```ts
const vault = new VaultSlotStore("vault", client, { vaultKid: "<kid of the vault slot>" });
await vault.writeAsync({ path: "scada/mqtt", content: { kind: "keys", data: { host, port, username, password } } });
await vault.writeAsync({
    path: "scada/mosquitto-ca",
    content: { kind: "file", file: { name: "ca.crt", contentType: "application/x-pem-file", encoding: "utf8", content: pem } },
});
await vault.shareAsync({ path: "scada/mqtt", audiences: ["mqtt"] });
```

Any MQTT slot:

```ts
const vault = new VaultSlotStore("vault", client); // a fresh key pair per process: nothing it reads outlives it
const { content } = await vault.readAsync({ path: "scada/mqtt" });
```

## Tools

| tool | broker capability |
|---|---|
| `vault.capabilities` | none; gives the slot's public key and `kid` |
| `vault.list`, `vault.describe` | `vault.read` on the secret or one of its audiences (others left out); never the content |
| `vault.read` | `vault.read` on the secret or one of its audiences; content sealed for the `recipient` key |
| `vault.write` | `vault.write` on the secret, outcome reported; content sealed for the slot's key, `cas` optional |
| `vault.share` | `vault.share` on the secret and on each audience added, outcome reported |
| `vault.delete` | `vault.admin` on the secret, outcome reported |

A caller without the right gets `policy_denied` whether the secret exists or not: names cannot be probed.

## OpenBao

`OpenBaoVaultStore` uses a KV version 2 mount (`secret` by default) over the HTTP API, with no client library. It works with HashiCorp Vault as well.

- A `keys` secret is stored as its data, unchanged: `bao kv get` reads it natively. A file is stored as its fields plus the marker `@mcp-vault/kind`.
- Versions are KV versions, `cas` is KV's check-and-set, and `delete` removes the metadata (every version).
- The kind and the audiences sit in the entry's custom metadata (`mcp-vault.kind`, `mcp-vault.audiences`); other keys are left alone.
- `token` may be a function, for AppRole or Kubernetes auth. It never appears in an error.

Give the slot's token a policy restricted to its prefix:

```hcl
path "secret/data/mcp-vault/site1/*"     { capabilities = ["create", "read", "update"] }
path "secret/metadata/mcp-vault/site1/*" { capabilities = ["read", "list", "update", "delete"] }
path "secret/metadata/mcp-vault/site1"   { capabilities = ["list"] }
```

## Writing a store

Implement `ISecretStore`, then prove it:

```ts
import { describeVaultStoreConformance } from "@cyanmycelium/mcp-vault/conformance";

describeVaultStoreConformance("MyStore", () => new MyStore());
```

The suite pins the shared semantics: versions, check-and-set, `not_found`, listing by whole segments, audiences kept across writes, deletion, path and content validation, size limit. It runs unchanged through a slot, which proves that the sealed MCP form agrees with the TypeScript one.

## Develop

```sh
npm install
npm run typecheck
npm test
npm run build
```

Tests run against the sources. `tests/broker.test.ts` plays the scada and MQTT scenario against a real broker (`@cyanmycelium/mcp-broker/testing`) and checks that no secret crosses it in clear; `tests/conformance.test.ts` runs the suite on the memory store, on OpenBao through an in-process fake of its KV v2 API, and through a slot.

### Live tests

Against a real OpenBao, for instance in dev mode:

```sh
docker run --rm -p 127.0.0.1:8200:8200 -e BAO_DEV_ROOT_TOKEN_ID=dev-root -e BAO_DEV_LISTEN_ADDRESS=0.0.0.0:8200 openbao/openbao
BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN=dev-root npm run test:live
```

## License

Apache-2.0.
