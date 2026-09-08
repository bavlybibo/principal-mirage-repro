import assert from "node:assert/strict";
import test from "node:test";
import { AtlasGateApp } from "../app.js";
import { demo } from "../fixtures.js";

function expectBypass(seedMethod: string, seedPath: string, seedToken: string, followMethod: string, followPath: string, followToken: string) {
  const app = new AtlasGateApp("vulnerable");
  assert.equal(app.handle(seedMethod, seedPath, seedToken).status, 200);
  const follow = app.handle(followMethod, followPath, followToken);
  assert.equal(follow.status, 200);
  assert.equal(follow.resolution?.cacheHit, true);
  return follow;
}

test("cross-issuer viewer inherits admin principal", () => {
  const r = expectBypass("GET", "/api/tenants/acme/admin/export", demo.crossIssuer.corpAdmin(), "GET", "/api/tenants/acme/admin/export", demo.crossIssuer.partnerViewer());
  assert.equal(r.resolution?.claims.iss, "partner-idp");
  assert.equal(r.resolution?.principal.issuer, "corp-idp");
});

test("cross-tenant viewer inherits Acme admin principal", () => {
  const r = expectBypass("GET", "/api/tenants/acme/admin/export", demo.crossTenant.acmeAdmin(), "GET", "/api/tenants/acme/admin/export", demo.crossTenant.globexViewer());
  assert.equal(r.resolution?.claims.tenant, "globex");
  assert.equal(r.resolution?.principal.tenant, "acme");
});

test("password-only session inherits MFA assurance", () => {
  const r = expectBypass("POST", "/api/sensitive/rotate-key", demo.assurance.mfaAdmin(), "POST", "/api/sensitive/rotate-key", demo.assurance.passwordAdmin());
  assert.equal(r.resolution?.claims.acr, "password");
  assert.equal(r.resolution?.principal.assurance, "mfa");
});

test("direct context inherits delegated support context", () => {
  const r = expectBypass("GET", "/api/tenants/acme/support/summary", demo.delegation.delegatedSupport(), "GET", "/api/tenants/acme/support/summary", demo.delegation.directViewer());
  assert.equal(r.resolution?.claims.delegated ?? false, false);
  assert.equal(r.resolution?.principal.delegated, true);
});

test("new authz version inherits stale admin principal", () => {
  const r = expectBypass("GET", "/api/tenants/acme/admin/export", demo.revocation.before(), "GET", "/api/tenants/acme/admin/export", demo.revocation.after());
  assert.equal(r.resolution?.claims.authzVersion, 18);
  assert.equal(r.resolution?.principal.authzVersion, 17);
});

test("request order changes which context is incorrectly reused", () => {
  const app = new AtlasGateApp("vulnerable");
  const viewer = demo.crossIssuer.partnerViewer();
  const admin = demo.crossIssuer.corpAdmin();

  assert.equal(app.handle("GET", "/api/tenants/acme/admin/export", viewer).status, 403);
  const adminAfterViewer = app.handle("GET", "/api/tenants/acme/admin/export", admin);
  assert.equal(adminAfterViewer.status, 403);
  assert.equal(adminAfterViewer.resolution?.cacheHit, true);
  assert.equal(adminAfterViewer.resolution?.principal.role, "viewer");
});

test("legitimate same-context cache reuse still works", () => {
  const app = new AtlasGateApp("vulnerable");
  const admin = demo.crossIssuer.corpAdmin();
  assert.equal(app.handle("GET", "/api/tenants/acme/admin/export", admin).status, 200);
  const repeated = app.handle("GET", "/api/tenants/acme/admin/export", admin);
  assert.equal(repeated.status, 200);
  assert.equal(repeated.resolution?.cacheHit, true);
});
