import { createHmac, timingSafeEqual } from "node:crypto";
const AUDIENCE = "atlasgate-api";
const TRUSTED_ISSUERS = {
    "corp-idp": "corp-local-demo-secret",
    "partner-idp": "partner-local-demo-secret",
    "customer-idp": "customer-local-demo-secret"
};
function b64url(input) {
    return Buffer.from(input).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function decodeB64url(input) {
    const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
    const pad = "=".repeat((4 - (normalized.length % 4)) % 4);
    return Buffer.from(normalized + pad, "base64");
}
export function signLocalJwt(claims) {
    const finalClaims = { ...claims, aud: claims.aud ?? AUDIENCE, exp: claims.exp ?? Math.floor(Date.now() / 1000) + 3600 };
    const secret = TRUSTED_ISSUERS[finalClaims.iss];
    if (!secret) throw new Error(`Cannot sign for untrusted issuer: ${finalClaims.iss}`);
    const header = { alg: "HS256", typ: "JWT" };
    const encodedHeader = b64url(JSON.stringify(header));
    const encodedPayload = b64url(JSON.stringify(finalClaims));
    const signingInput = `${encodedHeader}.${encodedPayload}`;
    const sig = createHmac("sha256", secret).update(signingInput).digest();
    return `${signingInput}.${b64url(sig)}`;
}
export function verifyJwt(token) {
    const parts = token.split(".");
    if (parts.length !== 3) throw new Error("Malformed token");
    const [encodedHeader, encodedPayload, encodedSignature] = parts;
    const header = JSON.parse(decodeB64url(encodedHeader).toString("utf8"));
    if (header.alg !== "HS256") throw new Error("Unexpected algorithm");
    const claims = JSON.parse(decodeB64url(encodedPayload).toString("utf8"));
    const secret = TRUSTED_ISSUERS[claims.iss];
    if (!secret) throw new Error("Untrusted issuer");
    const signingInput = `${encodedHeader}.${encodedPayload}`;
    const expected = createHmac("sha256", secret).update(signingInput).digest();
    const actual = decodeB64url(encodedSignature);
    if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) throw new Error("Invalid signature");
    if (claims.aud !== AUDIENCE) throw new Error("Invalid audience");
    if (!Number.isInteger(claims.exp) || claims.exp <= Math.floor(Date.now() / 1000)) throw new Error("Expired token");
    return claims;
}
