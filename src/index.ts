// vault.v1, the contract
export * from "./contract/errors";
export * from "./contract/vault.types";
export * from "./contract/vault.store";
export * from "./contract/validation";

// End-to-end sealing
export * from "./crypto/envelope";

// Stores
export * from "./memory/memory.vault.store";
export * from "./openbao/openbao.vault.store";

// The slot: MCP surface, broker declaration, remote store.
// Broker-decided access comes from @cyanmycelium/mcp-uns.
export * from "./server/declaration";
export * from "./server/vault.behavior";
export * from "./server/vault.slot.store";
