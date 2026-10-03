import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

interface IVersion {
    readonly data: Record<string, unknown>;
    readonly created_time: string;
    deletion_time: string;
    destroyed: boolean;
}

interface IEntry {
    readonly versions: Map<number, IVersion>;
    current: number;
    custom: Record<string, string>;
    readonly created_time: string;
    updated_time: string;
}

export interface IFakeOpenBao {
    readonly address: string;
    /** Every request body the fake received, as text: what crossed the slot-to-OpenBao link. */
    readonly bodies: string[];
    /** Soft-deletes the current version, as `bao kv delete` would. */
    softDelete(path: string): void;
    clear(): void;
    stop(): Promise<void>;
}

/** OpenBao gives nanoseconds; the store must cope. */
const now = () => new Date().toISOString().replace("Z", "123456Z");

/**
 * The part of OpenBao's KV version 2 HTTP API the store uses, in memory, on
 * one mount (`secret`), with one token. Enough to test the store's mapping;
 * `tests/live` runs the same suite against a real OpenBao.
 */
export async function startFakeOpenBao(token: string): Promise<IFakeOpenBao> {
    const entries = new Map<string, IEntry>();
    const bodies: string[] = [];

    function send(response: ServerResponse, status: number, body?: unknown): void {
        response.writeHead(status, body === undefined ? {} : { "content-type": "application/json" });
        response.end(body === undefined ? undefined : JSON.stringify(body));
    }

    function handle(request: IncomingMessage, response: ServerResponse, text: string): void {
        if (request.headers["x-vault-token"] !== token) return send(response, 403, { errors: ["permission denied"] });
        const url = new URL(request.url ?? "/", "http://fake");
        const match = /^\/v1\/secret\/(data|metadata)\/?(.*)$/.exec(url.pathname);
        if (!match) return send(response, 404, { errors: [] });
        const area = match[1]!;
        const path = match[2]!.split("/").filter(Boolean).map(decodeURIComponent).join("/");
        const body = text ? JSON.parse(text) : {};
        const entry = entries.get(path);

        if (area === "data" && request.method === "GET") {
            const version = entry?.versions.get(Number(url.searchParams.get("version") ?? entry.current));
            if (!entry || !version || version.deletion_time || version.destroyed) return send(response, 404, { errors: [] });
            const number = Number(url.searchParams.get("version") ?? entry.current);
            return send(response, 200, {
                data: {
                    data: version.data,
                    metadata: { created_time: version.created_time, custom_metadata: entry.custom, deletion_time: "", destroyed: false, version: number },
                },
            });
        }
        if (area === "data" && request.method === "POST") {
            const cas = body.options?.cas;
            if (cas !== undefined && cas !== (entry?.current ?? 0)) {
                return send(response, 400, { errors: ["check-and-set parameter did not match the current version"] });
            }
            const time = now();
            const target = entry ?? { versions: new Map(), current: 0, custom: {}, created_time: time, updated_time: time };
            target.current += 1;
            target.updated_time = time;
            target.versions.set(target.current, { data: body.data, created_time: time, deletion_time: "", destroyed: false });
            entries.set(path, target);
            return send(response, 200, { data: { created_time: time, custom_metadata: target.custom, deletion_time: "", destroyed: false, version: target.current } });
        }
        if (area === "metadata" && request.method === "GET" && url.searchParams.get("list") === "true") {
            const folder = path ? `${path}/` : "";
            const keys = new Set<string>();
            for (const key of entries.keys()) {
                if (!key.startsWith(folder)) continue;
                const rest = key.slice(folder.length).split("/");
                keys.add(rest.length > 1 ? `${rest[0]}/` : rest[0]!);
            }
            if (keys.size === 0) return send(response, 404, { errors: [] });
            return send(response, 200, { data: { keys: [...keys].sort() } });
        }
        if (area === "metadata" && request.method === "GET") {
            if (!entry) return send(response, 404, { errors: [] });
            const versions = Object.fromEntries(
                [...entry.versions].map(([number, version]) => [
                    String(number),
                    { created_time: version.created_time, deletion_time: version.deletion_time, destroyed: version.destroyed },
                ])
            );
            return send(response, 200, {
                data: {
                    current_version: entry.current,
                    created_time: entry.created_time,
                    updated_time: entry.updated_time,
                    custom_metadata: entry.custom,
                    versions,
                    max_versions: 0,
                },
            });
        }
        if (area === "metadata" && request.method === "POST") {
            // As OpenBao: every custom metadata value holds 1 to 512 characters.
            for (const [key, value] of Object.entries(body.custom_metadata ?? {})) {
                if (typeof value !== "string" || value.length === 0 || value.length > 512) {
                    return send(response, 400, { errors: [`custom_metadata validation failed: length of value for key "${key}" must be 0 < len(value) <= 512`] });
                }
            }
            const time = now();
            const target = entry ?? { versions: new Map(), current: 0, custom: {}, created_time: time, updated_time: time };
            if (body.custom_metadata) target.custom = body.custom_metadata;
            entries.set(path, target);
            return send(response, 204);
        }
        if (area === "metadata" && request.method === "DELETE") {
            entries.delete(path);
            return send(response, 204);
        }
        return send(response, 405, { errors: ["unsupported operation"] });
    }

    const server = createServer((request, response) => {
        let text = "";
        request.setEncoding("utf8");
        request.on("data", (chunk: string) => (text += chunk));
        request.on("end", () => {
            if (text) bodies.push(text);
            try {
                handle(request, response, text);
            } catch (error) {
                send(response, 500, { errors: [String(error)] });
            }
        });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address() as AddressInfo;

    return {
        address: `http://127.0.0.1:${port}`,
        bodies,
        softDelete(path) {
            const entry = entries.get(path);
            const version = entry?.versions.get(entry.current);
            if (version) version.deletion_time = now();
        },
        clear() {
            entries.clear();
            bodies.length = 0;
        },
        stop: () => new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve()))),
    };
}
