import { defineConfig } from "vitest/config";
import base from "./vitest.config";

// Against a real OpenBao: BAO_ADDR and BAO_TOKEN must be set (see README, "Live tests").
export default defineConfig({
    resolve: base.resolve,
    test: {
        include: ["tests/live/**/*.test.ts"],
        environment: "node",
        testTimeout: 30_000,
    },
});
