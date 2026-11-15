// NullWeb Cookie Cloud reverse proxy
// Netlify Function
//
// Required environment variable:
// NULLWEB_API_ORIGIN=https://nullweb.org
//
// Client endpoint:
// /.netlify/functions/cookie-proxy?path=/api/cookie/save

const MAX_BODY_SIZE = 128 * 1024;

const CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Authorization, Content-Type",
    "Access-Control-Max-Age": "86400",
    "Access-Control-Expose-Headers": "ETag",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
};

function respond(body, status = 200, extraHeaders = {}) {
    return new Response(body, {
        status,
        headers: {
            ...CORS_HEADERS,
            "Content-Type": "application/json; charset=utf-8",
            ...extraHeaders
        }
    });
}

async function readLimitedBody(request) {
    if (!request.body) return new Uint8Array();

    const declaredLength = Number(request.headers.get("content-length"));

    if (Number.isFinite(declaredLength) && declaredLength > MAX_BODY_SIZE) {
        throw new Error("BODY_TOO_LARGE");
    }

    const reader = request.body.getReader();
    const chunks = [];
    let total = 0;

    try {
        while (true) {
            const { done, value } = await reader.read();

            if (done) break;

            total += value.byteLength;

            if (total > MAX_BODY_SIZE) {
                await reader.cancel();
                throw new Error("BODY_TOO_LARGE");
            }

            chunks.push(value);
        }
    } finally {
        reader.releaseLock();
    }

    const result = new Uint8Array(total);
    let offset = 0;

    for (const chunk of chunks) {
        result.set(chunk, offset);
        offset += chunk.byteLength;
    }

    return result;
}

function allowedMethod(path, method) {
    const routes = {
        "/api/cookie/status": ["GET"],
        "/api/cookie/save": ["GET", "PUT", "DELETE"]
    };

    return routes[path]?.includes(method) ?? false;
}

export default async (request) => {
    // Handle browser preflight.
    if (request.method === "OPTIONS") {
        return new Response(null, {
            status: 204,
            headers: CORS_HEADERS
        });
    }

    const requestUrl = new URL(request.url);

    // Only accept the intended function endpoint.
    if (requestUrl.pathname !== "/.netlify/functions/cookie-proxy") {
        return respond(JSON.stringify({ error: "Not found" }), 404);
    }

    const path = requestUrl.searchParams.get("path");
    const method = request.method;

    // Strict endpoint and method allowlist.
    if (!path || !allowedMethod(path, method)) {
        return respond(JSON.stringify({
            error: "Endpoint or method not allowed"
        }), 405);
    }

    // Validate the fixed upstream.
    const configuredOrigin = process.env.NULLWEB_API_ORIGIN;

    if (!configuredOrigin) {
        return respond(JSON.stringify({
            error: "Proxy is not configured"
        }), 500);
    }

    let origin;

    try {
        origin = new URL(configuredOrigin);

        if (
            origin.protocol !== "https:" ||
            origin.username ||
            origin.password ||
            origin.pathname !== "/" ||
            origin.search ||
            origin.hash
        ) {
            throw new Error("Invalid upstream origin");
        }
    } catch {
        return respond(JSON.stringify({
            error: "Invalid upstream configuration"
        }), 500);
    }

    // Build the upstream URL without accepting arbitrary destinations.
    const upstreamUrl = new URL(path, origin);

    // Forward query parameters except our own routing parameter.
    for (const [key, value] of requestUrl.searchParams) {
        if (key !== "path") {
            upstreamUrl.searchParams.append(key, value);
        }
    }

    // Forward only the headers the API actually needs.
    const headers = new Headers();

    for (const name of ["authorization", "content-type", "accept"]) {
        const value = request.headers.get(name);

        if (value) {
            headers.set(name, value);
        }
    }

    let body;

    if (method === "PUT") {
        try {
            body = await readLimitedBody(request);
        } catch (error) {
            if (error.message === "BODY_TOO_LARGE") {
                return respond(JSON.stringify({
                    error: "Request body too large",
                    maxSize: MAX_BODY_SIZE
                }), 413);
            }

            return respond(JSON.stringify({
                error: "Unable to read request body"
            }), 400);
        }
    }

    try {
        const upstream = await fetch(upstreamUrl, {
            method,
            headers,
            body,
            redirect: "manual",
            signal: AbortSignal.timeout(15000)
        });

        // Never follow redirects with an Authorization header.
        if (upstream.status >= 300 && upstream.status < 400) {
            return respond(JSON.stringify({
                error: "Unexpected upstream redirect"
            }), 502);
        }

        // Preserve useful response headers.
        const responseHeaders = {};

        for (const name of [
            "content-type",
            "etag",
            "last-modified",
            "retry-after"
        ]) {
            const value = upstream.headers.get(name);

            if (value) {
                responseHeaders[
                    name.replace(/(^|-)([a-z])/g, (_, a, b) =>
                        a + b.toUpperCase()
                    )
                ] = value;
            }
        }

        // Preserve upstream status and response body.
        const responseBody = [204, 205, 304].includes(upstream.status)
            ? null
            : upstream.body;

        return new Response(responseBody, {
            status: upstream.status,
            headers: {
                ...CORS_HEADERS,
                ...responseHeaders
            }
        });

    } catch {
        // Do not expose upstream errors or credentials.
        return respond(JSON.stringify({
            error: "Cookie Cloud upstream unavailable"
        }), 502);
    }
};
