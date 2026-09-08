import assert from "node:assert/strict";
import test from "node:test";
import { AtlasGateApp } from "../app.js";
import { demo } from "../fixtures.js";
function expectSeparated(seedMethod, seedPath, seedToken, followMethod, followPath, followToken) {
    const app = new AtlasGateApp("fixed");
    assert.equal(app.handle(seedMethod, seedPath, seedToken).status, 200);
    const follow = app.handle(followMethod, followPath, followToken);
    assert.equal(follow.status, 403);
    assert.equal(follow.resolution?.cacheHit, false);
    return follow;
}
test("cross-issuer contexts remain isolated", () => {
    expectSeparated("GET", "/api/tenants/acme/admin/export", demo.crossIssuer.corpAdmin(), "GET", "/api/tenants/acme/admin/export", demo.crossIssuer.partnerViewer());
});
test("cross-tenant contexts remain isolated", () => {
    expectSeparated("GET", "/api/tenants/acme/admin/export", demo.crossTenant.acmeAdmin(), "GET", "/api/tenants/acme/admin/export", demo.crossTenant.globexViewer());
});
test("MFA state is not reused by password-only context", () => {
    expectSeparated("POST", "/api/sensitive/rotate-key", demo.assurance.mfaAdmin(), "POST", "/api/sensitive/rotate-key", demo.assurance.passwordAdmin());
});
test("delegated support state is not reused by direct context", () => {
    expectSeparated("GET", "/api/tenants/acme/support/summary", demo.delegation.delegatedSupport(), "GET", "/api/tenants/acme/support/summary", demo.delegation.directViewer());
});
test("newer authorization version does not reuse stale admin state", () => {
    expectSeparated("GET", "/api/tenants/acme/admin/export", demo.revocation.before(), "GET", "/api/tenants/acme/admin/export", demo.revocation.after());
});
test("request order does not collapse distinct issuer contexts", () => {
    const app = new AtlasGateApp("fixed");
    const viewer = demo.crossIssuer.partnerViewer();
    const admin = demo.crossIssuer.corpAdmin();
    assert.equal(app.handle("GET", "/api/tenants/acme/admin/export", viewer).status, 403);
    assert.equal(app.handle("GET", "/api/tenants/acme/admin/export", admin).status, 200);
});
test("legitimate equivalent context is still cacheable", () => {
    const app = new AtlasGateApp("fixed");
    const admin = demo.crossIssuer.corpAdmin();
    const first = app.handle("GET", "/api/tenants/acme/admin/export", admin);
    const second = app.handle("GET", "/api/tenants/acme/admin/export", admin);
    assert.equal(first.status, 200);
    assert.equal(second.status, 200);
    assert.equal(first.resolution?.cacheHit, false);
    assert.equal(second.resolution?.cacheHit, true);
});
