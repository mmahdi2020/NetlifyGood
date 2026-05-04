const STRIP = new Set([
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
  "via"
]);

const PSK = "pk";

exports.handler = async (event) => {

  if (event.httpMethod !== "POST") {
    return { statusCode: 405, body: '{"e":"method_not_allowed"}' };
  }

  let body;
  try {
    body = JSON.parse(event.body);
  } catch {
    return { statusCode: 400, body: '{"e":"bad_json"}' };
  }

  if (!body || body.k !== PSK) {
    return { statusCode: 401, body: '{"e":"unauthorized"}' };
  }

  const url = body.u;
  if (!url || !/^https?:\/\//i.test(url)) {
    return { statusCode: 400, body: '{"e":"bad_url"}' };
  }

  const method = (body.m || "GET").toUpperCase();

  let headers = undefined;
  if (body.h && typeof body.h === "object") {
    headers = {};
    for (const k in body.h) {
      if (!STRIP.has(k.toLowerCase())) headers[k] = body.h[k];
    }
  }

  let payload;
  if (body.b) {
    payload = Buffer.from(body.b, "base64");
  }

  try {

    const r = await fetch(url, {
      method,
      headers,
      body: payload,
      redirect: "manual"
    });

    const buf = Buffer.from(await r.arrayBuffer());

    const rh = {};
    r.headers.forEach((v, k) => { rh[k] = v });

    return {
      statusCode: 200,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        s: r.status,
        h: rh,
        b: buf.toString("base64")
      })
    };

  } catch (e) {

    return {
      statusCode: 500,
      body: JSON.stringify({ e: String(e) })
    };

  }
};
