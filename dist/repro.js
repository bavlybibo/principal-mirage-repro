import assert from "node:assert/strict";
import { AtlasGateApp } from "./app.js";
import { demo } from "./fixtures.js";
import { verifyJwt } from "./jwt.js";
function section(title) { console.log(`\n=== ${title} ===`); }
function proveValid(name, jwt) {
    const claims = verifyJwt(jwt);
    console.log(`[verified] ${name}: iss=${claims.iss} sub=${claims.sub} tenant=${claims.tenant} role=${claims.role} acr=${claims.acr} delegated=${claims.delegated ?? false} authzVersion=${claims.authzVersion}`);
    return claims;
}
function logResponse(label, response) {
    const r = response.resolution;
    if (!r) { console.log(`[http] ${label}: status=${response.status}`); return; }
    console.log(`[http] ${label}: status=${response.status} cacheHit=${r.cacheHit} key=${r.cacheKey.slice(0, 20)} principal=${r.principal.issuer}/${r.principal.subject}/${r.principal.tenant}/${r.principal.role}/${r.principal.assurance}/delegated:${r.principal.delegated}/v${r.principal.authzVersion}`);
}
function crossIssuer(app) {
    section("1) Cross-issuer principal collision"); app.reset();
    const admin = demo.crossIssuer.corpAdmin(); const viewer = demo.crossIssuer.partnerViewer();
    proveValid("corp admin", admin); proveValid("partner viewer", viewer);
    const seed = app.handle("GET", "/api/tenants/acme/admin/export", admin);
    const bypass = app.handle("GET", "/api/tenants/acme/admin/export", viewer);
    logResponse("seed admin request", seed); logResponse("partner viewer request", bypass);
    assert.equal(seed.status, 200); assert.equal(bypass.status, 200);
    assert.equal(bypass.resolution?.claims.role, "viewer"); assert.equal(bypass.resolution?.principal.role, "admin");
    assert.equal(bypass.resolution?.claims.iss, "partner-idp"); assert.equal(bypass.resolution?.principal.issuer, "corp-idp");
    console.log("[BYPASS] valid partner viewer credential executed an Acme admin route with the corp admin principal");
}
function crossTenant(app) {
    section("2) Cross-tenant authorization state reuse"); app.reset();
    const acmeAdmin = demo.crossTenant.acmeAdmin(); const globexViewer = demo.crossTenant.globexViewer();
    proveValid("Acme admin", acmeAdmin); proveValid("Globex viewer", globexViewer);
    const seed = app.handle("GET", "/api/tenants/acme/admin/export", acmeAdmin);
    const bypass = app.handle("GET", "/api/tenants/acme/admin/export", globexViewer);
    logResponse("seed Acme admin", seed); logResponse("Globex-only viewer targeting Acme", bypass);
    assert.equal(seed.status, 200); assert.equal(bypass.status, 200);
    assert.equal(bypass.resolution?.claims.tenant, "globex"); assert.equal(bypass.resolution?.principal.tenant, "acme");
    console.log("[BYPASS] Globex viewer inherited Acme admin state and accessed an Acme-only admin route");
}
function assurance(app) {
    section("3) MFA assurance collapse"); app.reset();
    const mfa = demo.assurance.mfaAdmin(); const password = demo.assurance.passwordAdmin();
    proveValid("MFA admin", mfa); proveValid("password-only admin", password);
    const seed = app.handle("POST", "/api/sensitive/rotate-key", mfa);
    const bypass = app.handle("POST", "/api/sensitive/rotate-key", password);
    logResponse("seed MFA request", seed); logResponse("password-only request", bypass);
    assert.equal(seed.status, 200); assert.equal(bypass.status, 200);
    assert.equal(bypass.resolution?.claims.acr, "password"); assert.equal(bypass.resolution?.principal.assurance, "mfa");
    console.log("[BYPASS] password-only credential inherited cached MFA assurance for a sensitive action");
}
function delegation(app) {
    section("4) Delegation context collapse"); app.reset();
    const delegated = demo.delegation.delegatedSupport(); const direct = demo.delegation.directViewer();
    proveValid("delegated support context", delegated); proveValid("direct viewer context", direct);
    const seed = app.handle("GET", "/api/tenants/acme/support/summary", delegated);
    const bypass = app.handle("GET", "/api/tenants/acme/support/summary", direct);
    logResponse("seed delegated request", seed); logResponse("direct viewer request", bypass);
    assert.equal(seed.status, 200); assert.equal(bypass.status, 200);
    assert.equal(bypass.resolution?.claims.delegated ?? false, false); assert.equal(bypass.resolution?.principal.delegated, true);
    assert.equal(bypass.resolution?.principal.actor, "support-agent");
    console.log("[BYPASS] direct context inherited privileges valid only during approved support delegation");
}
function revocation(app) {
    section("5) Authorization-version staleness"); app.reset();
    const before = demo.revocation.before(); const after = demo.revocation.after();
    proveValid("pre-revocation admin", before); proveValid("post-revocation user", after);
    const seed = app.handle("GET", "/api/tenants/acme/admin/export", before);
    const bypass = app.handle("GET", "/api/tenants/acme/admin/export", after);
    logResponse("seed pre-revocation request", seed); logResponse("post-revocation request", bypass);
    assert.equal(seed.status, 200); assert.equal(bypass.status, 200);
    assert.equal(bypass.resolution?.claims.authzVersion, 18); assert.equal(bypass.resolution?.claims.role, "user");
    assert.equal(bypass.resolution?.principal.authzVersion, 17); assert.equal(bypass.resolution?.principal.role, "admin");
    console.log("[BYPASS] newer downgraded authorization context received stale cached admin state");
}
function fixedControl() {
    section("Control: same request chains against fixed resolver");
    const app = new AtlasGateApp("fixed");
    const cases = [
        ["cross-issuer", demo.crossIssuer.corpAdmin, demo.crossIssuer.partnerViewer, "GET", "/api/tenants/acme/admin/export"],
        ["cross-tenant", demo.crossTenant.acmeAdmin, demo.crossTenant.globexViewer, "GET", "/api/tenants/acme/admin/export"],
        ["assurance", demo.assurance.mfaAdmin, demo.assurance.passwordAdmin, "POST", "/api/sensitive/rotate-key"],
        ["delegation", demo.delegation.delegatedSupport, demo.delegation.directViewer, "GET", "/api/tenants/acme/support/summary"],
        ["authz-version", demo.revocation.before, demo.revocation.after, "GET", "/api/tenants/acme/admin/export"]
    ];
    for (const [name, seedFactory, attackerFactory, method, path] of cases) {
        app.reset(); const seed = app.handle(method, path, seedFactory()); const denied = app.handle(method, path, attackerFactory());
        console.log(`[fixed] ${name}: seed=${seed.status} follow-up=${denied.status}`);
        assert.equal(seed.status, 200); assert.equal(denied.status, 403);
    }
}
function main() {
    console.log("Principal Mirage v0.2 — reviewer-ready end-to-end reproduction");
    console.log("All credentials are locally signed by trusted simulated issuers and independently verified before principal-cache lookup.");
    console.log("The vulnerable resolver is exercised through HTTP-style application routes and policy checks, not direct policy helper calls.\n");
    const vulnerable = new AtlasGateApp("vulnerable");
    crossIssuer(vulnerable); crossTenant(vulnerable); assurance(vulnerable); delegation(vulnerable); revocation(vulnerable); fixedControl();
    console.log("\nPASS: reproduced 5 end-to-end authorization failures and confirmed the reference fix blocks all 5 chains.");
}
main();
