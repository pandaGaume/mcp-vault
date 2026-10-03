import { randomUUID } from "node:crypto";
import { describe } from "vitest";
import { OpenBaoVaultStore } from "@cyanmycelium/mcp-vault";
import { describeVaultStoreConformance } from "@cyanmycelium/mcp-vault/conformance";

const address = process.env.BAO_ADDR;
const token = process.env.BAO_TOKEN;
const mount = process.env.BAO_MOUNT ?? "secret";

/**
 * The conformance suite against a real OpenBao, each test under a prefix of
 * its own, removed afterwards. See the README, "Live tests".
 */
describe.skipIf(!address || !token)("OpenBao, live", () => {
    let prefix = "";
    const store = () => new OpenBaoVaultStore({ address: address!, token: token!, mount, prefix });

    describeVaultStoreConformance(
        `OpenBaoVaultStore at ${address}`,
        () => {
            prefix = `mcp-vault-conformance/${randomUUID()}`;
            return store();
        },
        {
            async cleanupAsync() {
                const leftover = store();
                for (const item of (await leftover.listAsync({})).items) await leftover.deleteAsync({ path: item.path });
            },
        }
    );
});
