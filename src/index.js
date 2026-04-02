/**
 * Hardened Cloudflare Logpush -> Grafana Loki forwarder
 *
 * Security features:
 * - Shared-secret auth at the Worker edge (X-Logpush-Token)
 * - Size limits (compressed + decompressed) and max line count
 * - Safe decompression with streaming limit
 * - PII redaction knobs (strip headers/cookies; optionally strip URI query strings)
 * - Controlled Loki labels (static labels + job label only)
 *
 * Expected inputs:
 * - Cloudflare Logpush sends NDJSON, typically gzipped, to an HTTP destination. This Worker
 *   transforms NDJSON lines into Loki push API format and forwards them onward. [1](https://github.com/pew/cloudflare-worker-logpush-loki)
 */

function toBool(v, def = false) {
  if (v === undefined || v === null) return def;
  const s = String(v).trim().toLowerCase();
  return s === "1" || s === "true" || s === "yes" || s === "on";
}

function toInt(v, def) {
  const n = Number.parseInt(String(v), 10);
  return Number.isFinite(n) ? n : def;
}

/**
 * Timing-safe-ish compare for short tokens.
 * (CF Workers doesn't expose node crypto.timingSafeEqual; this is still better than ===
 * when attackers can measure micro-differences, which is limited in practice at the edge.)
 */
function constantTimeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
}

function safeJsonParse(line) {
  try {
    return JSON.parse(line);
  } catch {
    return null;
  }
}

function normalizeUnixNano(ts) {
  // Accepts:
  // - unix nano (18-20 digits)
  // - unix ms (13 digits)
  // - unix sec (10 digits)
  // - number or numeric string
  if (ts === undefined || ts === null) return null;
  const s = String(ts).trim();
  if (!/^\d+$/.test(s)) return null;

  if (s.length >= 18) return s; // already ns-ish
  if (s.length === 13) return String(Number(s) * 1_000_000);
  if (s.length === 10) return String(Number(s) * 1_000_000_000);
  // Anything else: treat as ms-ish if small, but safest to drop
  return null;
}

function parseStaticLabels(json) {
  if (!json) return {};
  try {
    const obj = JSON.parse(json);
    if (obj && typeof obj === "object" && !Array.isArray(obj)) {
      // Ensure all values are strings (Loki labels must be strings)
      const out = {};
      for (const [k, v] of Object.entries(obj)) out[String(k)] = String(v);
      return out;
    }
  } catch {
    // ignore
  }
  return {};
}

function redactObject(obj, redactKeysSet, stripQuery) {
  if (!obj || typeof obj !== "object") return obj;

  // Remove explicit keys
  for (const k of Object.keys(obj)) {
    if (redactKeysSet.has(k)) delete obj[k];
  }

  // Common-ish safety: drop any headers-like fields if caller asked (via defaults)
  // (You can widen this if desired, but keep it explicit.)
  // e.g. "RequestHeaders", "ResponseHeaders" are in default REDACT_KEYS.
  if (stripQuery && typeof obj.ClientRequestURI === "string") {
    const idx = obj.ClientRequestURI.indexOf("?");
    if (idx !== -1) obj.ClientRequestURI = obj.ClientRequestURI.slice(0, idx);
  }

  return obj;
}

/**
 * Reads a ReadableStream<Uint8Array> into a Uint8Array up to `limit` bytes.
 * If limit is exceeded, throws.
 */
async function readStreamWithLimit(stream, limit) {
  const reader = stream.getReader();
  const chunks = [];
  let total = 0;

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    if (value) {
      total += value.byteLength;
      if (total > limit) throw new Error("Decompressed payload exceeded limit");
      chunks.push(value);
    }
  }

  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.byteLength;
  }
  return out;
}

async function gunzipWithLimit(arrayBuffer, limitBytes) {
  // Prefer DecompressionStream when available (native in Workers),
  // fall back to pako if needed (repo already includes pako). [1](https://github.com/pew/cloudflare-worker-logpush-loki)[5](https://github.com/pew/cloudflare-worker-logpush-loki/blob/main/package-lock.json)
  if (typeof DecompressionStream !== "undefined") {
    const ds = new DecompressionStream("gzip");
    const stream = new Blob([arrayBuffer]).stream().pipeThrough(ds);
    return await readStreamWithLimit(stream, limitBytes);
  }

  // Fallback: pako (only if bundled)
  // eslint-disable-next-line no-undef
  const { inflate } = await import("pako");
  const inflated = inflate(new Uint8Array(arrayBuffer));
  if (inflated.byteLength > limitBytes) throw new Error("Decompressed payload exceeded limit");
  return inflated;
}

function buildLokiPayload(lines, jobName, staticLabels) {
  return {
    streams: [
      {
        stream: {
          job: jobName,
          ...staticLabels,
        },
        values: lines,
      },
    ],
  };
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Simple health endpoint
    if (request.method === "GET" && (url.pathname === "/health" || url.pathname === "/")) {
      return new Response("ok", { status: 200 });
    }

    if (request.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    // ---- Config (vars + secrets) ----
    const REQUIRED = {
      LOKI_PUSH_URL: env.LOKI_PUSH_URL,
      LOGPUSH_TOKEN: env.LOGPUSH_TOKEN, // secret
    };

    if (!REQUIRED.LOKI_PUSH_URL) return new Response("Server misconfigured: LOKI_PUSH_URL", { status: 500 });
    if (!REQUIRED.LOGPUSH_TOKEN) return new Response("Server misconfigured: LOGPUSH_TOKEN", { status: 500 });

    // Loki auth is optional (depends on your Loki)
    const lokiAuthHeader = env.LOKI_AUTH_HEADER ? String(env.LOKI_AUTH_HEADER) : null;

    const maxCompressedBytes = toInt(env.MAX_COMPRESSED_BYTES, 5_000_000);     // 5 MB default
    const maxDecompressedBytes = toInt(env.MAX_DECOMPRESSED_BYTES, 25_000_000); // 25 MB default
    const maxLines = toInt(env.MAX_LINES, 5_000);

    const redactKeys = String(env.REDACT_KEYS || "Cookies,RequestHeaders,ResponseHeaders")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    const redactKeysSet = new Set(redactKeys);

    const stripQuery = toBool(env.STRIP_QUERY_FROM_URI, true);
    const staticLabels = parseStaticLabels(env.STATIC_LABELS_JSON);

    // Job label comes from the existing README pattern: destination_conf has &job=lokiJobName [1](https://github.com/pew/cloudflare-worker-logpush-loki)
    const jobName = url.searchParams.get("job") || env.DEFAULT_JOB || "cloudflare_logpush";

    // ---- Authenticate request at edge ----
    // Cloudflare Logpush can add headers to destination requests via destination_conf query params. [1](https://github.com/pew/cloudflare-worker-logpush-loki)
    const providedToken = request.headers.get("X-Logpush-Token") || "";
    if (!constantTimeEqual(providedToken, String(env.LOGPUSH_TOKEN))) {
      return new Response("Unauthorized", { status: 401 });
    }

    // ---- Size limits (compressed) ----
    const contentLength = request.headers.get("content-length");
    if (contentLength) {
      const n = Number(contentLength);
      if (Number.isFinite(n) && n > maxCompressedBytes) {
        return new Response("Payload too large", { status: 413 });
      }
    }

    let bodyBuf = await request.arrayBuffer();
    if (bodyBuf.byteLength > maxCompressedBytes) {
      return new Response("Payload too large", { status: 413 });
    }

    // ---- Decode / decompress ----
    const encoding = (request.headers.get("content-encoding") || "").toLowerCase();
    let text;

    try {
      if (encoding === "gzip") {
        const inflated = await gunzipWithLimit(bodyBuf, maxDecompressedBytes);
        text = new TextDecoder("utf-8").decode(inflated);
      } else {
        // Initial Logpush verification payload may be uncompressed according to repo README. [1](https://github.com/pew/cloudflare-worker-logpush-loki)
        if (bodyBuf.byteLength > maxDecompressedBytes) {
          return new Response("Payload too large", { status: 413 });
        }
        text = new TextDecoder("utf-8").decode(new Uint8Array(bodyBuf));
      }
    } catch (e) {
      // Avoid echoing detailed errors to prevent info leakage
      return new Response("Bad Request", { status: 400 });
    }

    // ---- Parse NDJSON -> Loki values ----
    const rawLines = text.split("\n").filter((l) => l && l.trim().length > 0);
    if (rawLines.length > maxLines) {
      return new Response("Too many log lines", { status: 413 });
    }

    const values = [];
    for (let i = 0; i < rawLines.length; i++) {
      const line = rawLines[i];

      const obj = safeJsonParse(line);
      if (obj) {
        redactObject(obj, redactKeysSet, stripQuery);

        // Cloudflare example uses &timestamps=unixnano in logpull_options. [1](https://github.com/pew/cloudflare-worker-logpush-loki)
        const ts =
          normalizeUnixNano(obj.EdgeStartTimestamp) ||
          normalizeUnixNano(obj.EdgeEndTimestamp) ||
          String(Date.now() * 1_000_000);

        values.push([ts, JSON.stringify(obj)]);
      } else {
        // If a line isn't valid JSON, still forward it as plain text (defensive)
        values.push([String(Date.now() * 1_000_000), line]);
      }
    }

    if (values.length === 0) {
      return new Response(null, { status: 204 });
    }

    const lokiPayload = buildLokiPayload(values, jobName, staticLabels);

    // ---- Forward to Loki ----
    const headers = {
      "content-type": "application/json",
    };
    if (lokiAuthHeader) headers["authorization"] = lokiAuthHeader;

    // Use waitUntil so the Worker can respond quickly while Loki ingest happens in the background
    // (Useful under load; avoids holding client connection open.)
    const forward = fetch(String(env.LOKI_PUSH_URL), {
      method: "POST",
      headers,
      body: JSON.stringify(lokiPayload),
    });

    ctx.waitUntil(forward);

    // Return success to Logpush quickly
    return new Response(null, { status: 204 });
  },
};
