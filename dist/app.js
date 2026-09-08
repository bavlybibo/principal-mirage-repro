import { PrincipalResolver } from "./principal.js";
import { canAdminTenant, canPerformSensitiveAction, canReadOwnPrincipal, canUseDelegatedSupport } from "./policy.js";
function unauthorized(message) { return { status: 401, body: { error: message } }; }
function forbidden(message, resolution) { return { status: 403, body: { error: message }, resolution }; }
export class AtlasGateApp {
    mode;
    resolver;
    constructor(mode) { this.mode = mode; this.resolver = new PrincipalResolver(mode); }
    reset() { this.resolver.clear(); }
    handle(method, path, token) {
        if (method === "GET" && path === "/health") return { status: 200, body: { ok: true, mode: this.mode } };
        if (!token) return unauthorized("missing bearer token");
        let resolution;
        try { resolution = this.resolver.resolve(token); }
        catch (error) { return unauthorized(error instanceof Error ? error.message : "invalid credential"); }
        if (method === "GET" && path === "/api/me") {
            if (!canReadOwnPrincipal(resolution.principal)) return forbidden("principal rejected", resolution);
            return { status: 200, body: { authenticatedClaims: resolution.claims, authorizationPrincipal: resolution.principal, cache: { hit: resolution.cacheHit, key: resolution.cacheKey } }, resolution };
        }
        const adminMatch = path.match(/^\/api\/tenants\/([^/]+)\/admin\/export$/);
        if (method === "GET" && adminMatch) {
            const tenant = decodeURIComponent(adminMatch[1]);
            if (!canAdminTenant(resolution.principal, tenant)) return forbidden("admin role required for target tenant", resolution);
            return { status: 200, body: { exported: true, tenant, authorizedAs: resolution.principal }, resolution };
        }
        if (method === "POST" && path === "/api/sensitive/rotate-key") {
            if (!canPerformSensitiveAction(resolution.principal)) return forbidden("admin + MFA + direct context required", resolution);
            return { status: 200, body: { rotated: true, authorizedAs: resolution.principal }, resolution };
        }
        const delegatedMatch = path.match(/^\/api\/tenants\/([^/]+)\/support\/summary$/);
        if (method === "GET" && delegatedMatch) {
            const tenant = decodeURIComponent(delegatedMatch[1]);
            if (!canUseDelegatedSupport(resolution.principal, tenant)) return forbidden("approved delegated support context required", resolution);
            return { status: 200, body: { supportSummary: true, tenant, authorizedAs: resolution.principal }, resolution };
        }
        return { status: 404, body: { error: "route not found" }, resolution };
    }
}
