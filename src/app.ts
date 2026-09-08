import type { ApiResponse, ResolverMode } from "./types.js";
import { PrincipalResolver } from "./principal.js";
import {
  canAdminTenant,
  canPerformSensitiveAction,
  canReadOwnPrincipal,
  canUseDelegatedSupport
} from "./policy.js";

function unauthorized(message: string): ApiResponse {
  return { status: 401, body: { error: message } };
}

function forbidden(message: string, resolution: ReturnType<PrincipalResolver["resolve"]>): ApiResponse {
  return { status: 403, body: { error: message }, resolution };
}

export class AtlasGateApp {
  public readonly resolver: PrincipalResolver;

  public constructor(public readonly mode: ResolverMode) {
    this.resolver = new PrincipalResolver(mode);
  }

  public reset(): void {
    this.resolver.clear();
  }

  public handle(method: string, path: string, token?: string): ApiResponse {
    if (method === "GET" && path === "/health") {
      return { status: 200, body: { ok: true, mode: this.mode } };
    }

    if (!token) return unauthorized("missing bearer token");

    let resolution: ReturnType<PrincipalResolver["resolve"]>;
    try {
      resolution = this.resolver.resolve(token);
    } catch (error) {
      return unauthorized(error instanceof Error ? error.message : "invalid credential");
    }

    if (method === "GET" && path === "/api/me") {
      if (!canReadOwnPrincipal(resolution.principal)) return forbidden("principal rejected", resolution);
      return {
        status: 200,
        body: {
          authenticatedClaims: resolution.claims,
          authorizationPrincipal: resolution.principal,
          cache: { hit: resolution.cacheHit, key: resolution.cacheKey }
        },
        resolution
      };
    }

    const adminMatch = path.match(/^\/api\/tenants\/([^/]+)\/admin\/export$/);
    if (method === "GET" && adminMatch) {
      const tenant = decodeURIComponent(adminMatch[1]);
      if (!canAdminTenant(resolution.principal, tenant)) {
        return forbidden("admin role required for target tenant", resolution);
      }
      return {
        status: 200,
        body: { exported: true, tenant, authorizedAs: resolution.principal },
        resolution
      };
    }

    if (method === "POST" && path === "/api/sensitive/rotate-key") {
      if (!canPerformSensitiveAction(resolution.principal)) {
        return forbidden("admin + MFA + direct context required", resolution);
      }
      return {
        status: 200,
        body: { rotated: true, authorizedAs: resolution.principal },
        resolution
      };
    }

    const delegatedMatch = path.match(/^\/api\/tenants\/([^/]+)\/support\/summary$/);
    if (method === "GET" && delegatedMatch) {
      const tenant = decodeURIComponent(delegatedMatch[1]);
      if (!canUseDelegatedSupport(resolution.principal, tenant)) {
        return forbidden("approved delegated support context required", resolution);
      }
      return {
        status: 200,
        body: { supportSummary: true, tenant, authorizedAs: resolution.principal },
        resolution
      };
    }

    return { status: 404, body: { error: "route not found" }, resolution };
  }
}
