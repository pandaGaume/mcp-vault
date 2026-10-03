import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const source = (path: string) => fileURLToPath(new URL(`./src/${path}`, import.meta.url));

// Tests run against the sources: no build needed.
export default defineConfig({
    resolve: {
        alias: [
            { find: "@cyanmycelium/mcp-vault/conformance", replacement: source("conformance/index.ts") },
            { find: /^@cyanmycelium\/mcp-vault$/, replacement: source("index.ts") },
        ],
    },
    test: {
        include: ["tests/**/*.test.ts"],
        exclude: ["tests/live/**"],
        environment: "node",
    },
});
