import { createHash } from "node:crypto";
import { verifyJwt } from "./jwt.js";
function resolvePrincipal(claims) {
    return {
        issuer: claims.iss,
        subject: claims.sub,
        tenant: claims.tenant,
        role: claims.role,
        assurance: claims.acr,
        delegated: claims.delegated ?? false,
        actor: claims.actor,
        authzVersion: claims.authzVersion
    };
}
function vulnerableKey(claims) {
    return claims.sub;
}
function fixedKey(claims) {
    const canonical = JSON.stringify([
        claims.iss,
        claims.sub,
        claims.tenant,
        claims.role,
        claims.acr,
        claims.delegated ?? false,
        claims.actor ?? null,
        claims.authzVersion
    ]);
    return createHash("sha256").update(canonical).digest("hex");
}
export class PrincipalResolver {
    mode;
    cache = new Map();
    constructor(mode) {
        this.mode = mode;
    }
    clear() {
        this.cache.clear();
    }
    resolve(token) {
        const claims = verifyJwt(token);
        const cacheKey = this.mode === "vulnerable" ? vulnerableKey(claims) : fixedKey(claims);
        const cached = this.cache.get(cacheKey);
        if (cached) {
            return { claims, principal: cached, cacheHit: true, cacheKey };
        }
        const principal = resolvePrincipal(claims);
        this.cache.set(cacheKey, principal);
        return { claims, principal, cacheHit: false, cacheKey };
    }
}
