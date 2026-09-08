import type { Principal } from "./types.js";

export function canReadOwnPrincipal(principal: Principal): boolean {
  return Boolean(principal.subject);
}

export function canAdminTenant(principal: Principal, tenant: string): boolean {
  return principal.role === "admin" && principal.tenant === tenant;
}

export function canPerformSensitiveAction(principal: Principal): boolean {
  return principal.role === "admin" && principal.assurance === "mfa" && !principal.delegated;
}

export function canUseDelegatedSupport(principal: Principal, tenant: string): boolean {
  return (
    principal.role === "admin" &&
    principal.tenant === tenant &&
    principal.delegated === true &&
    principal.actor === "support-agent"
  );
}
