import { createHash } from "node:crypto";
import type { JwtClaims, Principal, ResolutionResult, ResolverMode } from "./types.js";
import { verifyJwt } from "./jwt.js";

function resolvePrincipal(claims: JwtClaims): Principal {
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

function vulnerableKey(claims: JwtClaims): string {
  // Intentional vulnerability: `sub` is only unique inside an issuer namespace,
  // and it does not describe tenant, assurance, delegation, or authz lifetime.
  return claims.sub;
}

function fixedKey(claims: JwtClaims): string {
  // Reviewer reference fix: explicitly serialize every security fact represented
  // by the cached Principal, then hash the canonical tuple into a compact key.
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
  private readonly cache = new Map<string, Principal>();

  public constructor(private readonly mode: ResolverMode) {}

  public clear(): void {
    this.cache.clear();
  }

  public resolve(token: string): ResolutionResult {
    // Authentication is intentionally performed before any principal-cache lookup.
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
