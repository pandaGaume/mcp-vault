import { VaultError, invalid } from "./errors";
import { FILE_ENCODINGS, type FileEncoding, type ISecretContent, type SecretPath } from "./vault.types";

const SEGMENT = /^[A-Za-z0-9_][A-Za-z0-9._-]*$/;
const AUDIENCE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export const MAX_PATH_LENGTH = 512;
export const MAX_PATH_SEGMENTS = 16;
export const MAX_AUDIENCES = 32;
export const MAX_FILE_NAME_LENGTH = 255;

/** Data keys starting with this prefix are reserved for the stores' own bookkeeping. */
export const RESERVED_KEY_PREFIX = "@mcp-vault/";

/** A secret path, or `invalid_request`. */
export function parseSecretPath(value: unknown, label = "path"): SecretPath {
    if (typeof value !== "string" || value.length === 0) throw invalid(`${label} must be a non-empty string`);
    if (value.length > MAX_PATH_LENGTH) throw invalid(`${label} is longer than ${MAX_PATH_LENGTH} characters`);
    const segments = value.split("/");
    if (segments.length > MAX_PATH_SEGMENTS) throw invalid(`${label} has more than ${MAX_PATH_SEGMENTS} segments`);
    for (const segment of segments) {
        if (!SEGMENT.test(segment)) throw invalid(`${label} "${value}" has an invalid segment "${segment}"`, { path: value });
    }
    return value;
}

/** A subtree for `list`: `""` for everything. */
export function parsePrefix(value: unknown): SecretPath {
    if (value === undefined || value === null || value === "") return "";
    return parseSecretPath(value, "prefix");
}

/** Whether `path` lies in the subtree `prefix`, by whole segments. */
export function isUnder(path: SecretPath, prefix: SecretPath): boolean {
    return prefix === "" || path === prefix || path.startsWith(`${prefix}/`);
}

export function isAudience(value: unknown): value is string {
    return typeof value === "string" && AUDIENCE.test(value);
}

/** A complete audience set: valid names, without duplicates, sorted. */
export function parseAudiences(value: unknown): string[] {
    if (!Array.isArray(value)) throw invalid("audiences must be an array");
    if (value.length > MAX_AUDIENCES) throw new VaultError("limit_exceeded", `a secret is shared with ${MAX_AUDIENCES} audiences at most`);
    for (const item of value) {
        if (!isAudience(item)) throw invalid(`audience ${JSON.stringify(item)} is not a lowercase name of letters, digits, ".", "_" or "-"`);
    }
    return [...new Set(value as string[])].sort();
}

/** An optional positive integer version. */
export function parseVersion(value: unknown): number | undefined {
    if (value === undefined || value === null) return undefined;
    if (!Number.isSafeInteger(value) || (value as number) < 1) throw invalid("version must be a positive integer");
    return value as number;
}

/** An optional check-and-set version: `0` or a positive integer. */
export function parseCas(value: unknown): number | undefined {
    if (value === undefined || value === null) return undefined;
    if (!Number.isSafeInteger(value) || (value as number) < 0) throw invalid("cas must be 0 or a positive integer");
    return value as number;
}

/** The page size of `list`, within the store's limit. */
export function parseLimit(value: unknown, max: number): number {
    if (value === undefined || value === null) return max;
    if (!Number.isSafeInteger(value) || (value as number) < 1) throw invalid("limit must be a positive integer");
    return Math.min(value as number, max);
}

export function isPlainObject(value: unknown): value is Record<string, unknown> {
    if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
    const proto = Object.getPrototypeOf(value);
    return proto === Object.prototype || proto === null;
}

/** Validates a secret's content and its size; returns a copy that shares nothing with the input. */
export function parseContent(value: unknown, maxBytes: number): ISecretContent {
    if (!isPlainObject(value)) throw invalid("content must be an object");
    let content: ISecretContent;
    if (value.kind === "keys") {
        if (!isPlainObject(value.data)) throw invalid("content.data must be a JSON object");
        for (const key of Object.keys(value.data)) {
            if (key.startsWith(RESERVED_KEY_PREFIX)) throw invalid(`content.data key "${key}" is reserved`);
        }
        content = { kind: "keys", data: value.data };
    } else if (value.kind === "file") {
        const file = value.file;
        if (!isPlainObject(file)) throw invalid("content.file must be an object");
        if (typeof file.name !== "string" || file.name.length === 0 || file.name.length > MAX_FILE_NAME_LENGTH) {
            throw invalid(`content.file.name must be a string of 1 to ${MAX_FILE_NAME_LENGTH} characters`);
        }
        if (typeof file.contentType !== "string" || file.contentType.length === 0) throw invalid("content.file.contentType must be a non-empty string");
        if (!FILE_ENCODINGS.includes(file.encoding as FileEncoding)) throw invalid(`content.file.encoding must be one of ${FILE_ENCODINGS.join(", ")}`);
        if (typeof file.content !== "string") throw invalid("content.file.content must be a string");
        if (file.encoding === "base64" && !BASE64.test(file.content)) throw invalid("content.file.content is not valid base64");
        content = { kind: "file", file: { name: file.name, contentType: file.contentType, encoding: file.encoding as FileEncoding, content: file.content } };
    } else {
        throw invalid('content.kind must be "keys" or "file"');
    }
    let json: string;
    try {
        json = JSON.stringify(content);
    } catch {
        throw invalid("content must be serializable as JSON");
    }
    const bytes = Buffer.byteLength(json, "utf8");
    if (bytes > maxBytes) throw new VaultError("limit_exceeded", `content is ${bytes} bytes, the store accepts ${maxBytes} at most`, { detail: { bytes, maxBytes } });
    return JSON.parse(json) as ISecretContent;
}

/** Normalizes an RFC 3339 instant (OpenBao gives nanoseconds) to UTC ISO 8601 at the millisecond. */
export function toIsoInstant(value: unknown): string {
    if (typeof value !== "string") return new Date(0).toISOString();
    const trimmed = value.replace(/(\.\d{3})\d+/, "$1");
    const time = Date.parse(trimmed);
    return Number.isNaN(time) ? new Date(0).toISOString() : new Date(time).toISOString();
}
