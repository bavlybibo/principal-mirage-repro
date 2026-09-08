export function canReadOwnPrincipal(principal) {
    return Boolean(principal.subject);
}
export function canAdminTenant(principal, tenant) {
    return principal.role === "admin" && principal.tenant === tenant;
}
export function canPerformSensitiveAction(principal) {
    return principal.role === "admin" && principal.assurance === "mfa" && !principal.delegated;
}
export function canUseDelegatedSupport(principal, tenant) {
    return (principal.role === "admin" &&
        principal.tenant === tenant &&
        principal.delegated === true &&
        principal.actor === "support-agent");
}
