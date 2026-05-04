// MasterHttpRelay (Netlify port of val.town version)
// Secure relay - use only with a strong PSK set in Environment Variables (PSK)

const STRIP_HEADERS = new Set([
  "host",
  "connection",
  "content-length",
  "transfer-encoding",
  "proxy-connection",
  "proxy-authorization",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-proto",
  "x-forwarded-port",
  "x-real-ip",
  "forwarded",
  "via",
]);

function decodeBase64ToBytes(input) {
  const buf = Buffer.from(input, "base64");
  return new Uint8Array(buf);
}

function encodeBytesToBase64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

function sanitizeHeaders(h) {
  const out = {};
  if (!h || typeof h !== "object") return out;
  for (const [k, v] of Object.entries(h)) {
    if (!k) continue;
    if (STRIP_HEADERS.has(k.toLowerCase())) continue;
    out[k] = String(v ?? "");
  }
  return out;
}

exports.handler = async (event) => {
  try {
    if (event.httpMethod !== "POST") {
      return {
        statusCode: 405,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ e: "method_not_allowed" }),
      };
    }

    let body;
    try {
      body = JSON.parse(event.body || "{}");
    } catch {
      return {
        statusCode: 400,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ e: "bad_json" }),
      };
    }

    if (!body || typeof body !== "object") {
      return {
        statusCode: 400,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ e: "bad_json" }),
      };
    }

    const PSK = process.env.PSK || "CHANGE_ME_TO_A_STRONG_SECRET";

    const k = String(body.k ?? "");
    const u = String(body.u ?? "");
    const m = String(body.m ?? "GET").toUpperCase();
    const h = sanitizeHeaders(body.h);
    const b64 = body.b;

    if (k !== PSK) {
      return {
        statusCode: 401,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ e: "unauthorized" }),
      };
    }

    if (!/^https?:\/\//i.test(u)) {
      return {
        statusCode: 400,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ e: "bad url" }),
      };
    }

    let payload;
    if (typeof b64 === "string" && b64.length > 0) {
      payload = decodeBase64ToBytes(b64);
    }

    const resp = await fetch(u, {
      method: m,
      headers: h,
      body: payload,
      redirect: "manual",
    });

    const data = new Uint8Array(await resp.arrayBuffer());

    const respHeaders = {};
    resp.headers.forEach((value, key) => {
      respHeaders[key] = value;
    });

    return {
      statusCode: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        s: resp.status,
        h: respHeaders,
        b: encodeBytesToBase64(data),
      }),
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      statusCode: 500,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ e: message }),
    };
  }
};
