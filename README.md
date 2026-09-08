# Principal Mirage v0.2 — Reviewer-Ready Working Reproduction

This repository is the **self-contained working code sample** for the proposal **Principal Mirage — Authorization Bypass Through Security Context Collapse**.

It is intentionally optimized for proposal review: the vulnerability is easy to reproduce and inspect here. The eventual player-facing SecDim Play challenge should preserve the same security invariant failure while making discovery materially harder through realistic resolver/cache/policy boundaries and adversarial tests.

## 30-second reviewer path

Node.js 20+ is sufficient. Compiled JavaScript is included.

```bash
node dist/repro.js
```

Expected final line:

```text
PASS: reproduced 5 end-to-end authorization failures and confirmed the reference fix blocks all 5 chains.
```

For a complete rebuild and test run:

```bash
npm install
npm run review
```

## What changed from the original minimal PoC

v0.2 moves the reproduction from direct cache/policy helper calls to a small **AtlasGate application layer** with HTTP-style routes:

- `GET /api/me`
- `GET /api/tenants/:tenant/admin/export`
- `POST /api/sensitive/rotate-key`
- `GET /api/tenants/:tenant/support/summary`

The flow is now:

```text
Bearer credential
      ↓
JWT verification
      ↓
Principal resolver
      ↓
Principal cache
      ↓
Policy engine
      ↓
Application route
```

Every demonstrated JWT is independently verified **before** the principal cache is consulted.

## The vulnerable security boundary

The vulnerable resolver caches authorization state using only JWT `sub`:

```ts
return claims.sub;
```

That equality relation is too weak for the object being cached. A `Principal` also represents issuer namespace, tenant authority, authentication assurance, delegation state, actor identity, and authorization version.

The code therefore authenticates one credential correctly but can authorize the request with another security context.

## Five demonstrated end-to-end failures

### 1. Cross-issuer collision

A valid `corp-idp` admin credential populates the principal cache. A separate valid `partner-idp` viewer credential with the same `sub` is then accepted cryptographically but receives the corp administrator principal and reaches an admin route.

### 2. Cross-tenant isolation failure

The same subject is an admin in Acme and a viewer in Globex. After Acme state is cached, the Globex-only credential can target the Acme admin route because the cached Acme principal is reused.

### 3. Authentication-assurance collapse

An MFA-authenticated admin context populates the cache. A later password-only credential for the same subject inherits `assurance=mfa` and reaches the sensitive key-rotation route.

### 4. Delegation isolation failure

A temporary approved support-delegation context populates the cache. A direct, non-delegated viewer context for the same subject then inherits the delegated support principal and reaches the support-only route.

### 5. Authorization-version staleness

An admin context at `authzVersion=17` populates the cache. A newer valid credential at `authzVersion=18` reflects a downgrade to `user`, but the older admin principal is returned and still reaches the admin route.

No scenario uses token forgery, an invalid signature, `alg=none`, audience confusion, expired credentials, brute force, or an external service.

## Request-order behavior

The vulnerable test suite also reverses cache population order. This shows the problem is not a hard-coded privilege escalation string: the first security context stored under the incomplete equivalence key becomes the context reused later. Depending on order, the result can be privilege escalation or incorrect denial.

## Reference fixed implementation

The repository contains a parallel `fixed` resolver used only as a reviewer control. It builds a canonical tuple from every security fact represented by the cached principal and hashes that tuple for the cache key:

```text
issuer
subject
tenant
role
assurance
delegated
actor
authzVersion
```

This is deliberately presented as a compact reference remediation for the reproduction, not as a claim that every production authorization system should use exactly this tuple. The production rule is semantic:

> Cached security state may only be reused when the new request is authorization-equivalent to the context that produced that state.

A real system may instead avoid caching authorization principals, resolve live server-side authorization state, use short lifetimes plus revocation-aware invalidation, or define a different explicit security-context identity.

## Test commands

```bash
npm run build
npm run repro
npm run test:vulnerable
npm run test:fixed
npm run review
```

`test:vulnerable` passes only when the five intended failures are actually reproduced. `test:fixed` passes only when all five contexts remain isolated while legitimate same-context cache reuse still works.

## Optional local HTTP server

The same application can be run as a real localhost HTTP server:

```bash
npm run server:vulnerable
```

or:

```bash
npm run server:fixed
```

It binds only to `127.0.0.1:31337` and prints locally generated reviewer demo tokens. Example:

```bash
curl -H "Authorization: Bearer <TOKEN>" \
  http://127.0.0.1:31337/api/tenants/acme/admin/export
```

## Repository layout

```text
src/
  app.ts                 AtlasGate routes/application layer
  fixtures.ts            valid local test credentials
  http-server.ts         localhost HTTP adapter
  jwt.ts                 signing + cryptographic verification
  policy.ts              authorization policy checks
  principal.ts           vulnerable + reference-fixed cache semantics
  repro.ts               five end-to-end reproduction chains
  server.ts              standalone localhost runner
  tests/
    vulnerable.test.ts   exploit + request-order + usability checks
    fixed.test.ts        isolation + legitimate cache-reuse checks
```

Compiled JavaScript is included in `dist/` so a reviewer does not need TypeScript installed just to reproduce the issue.

## Scope of the proposal sample vs. final challenge

This sample is intentionally transparent because its job is to demonstrate that the proposed vulnerability is concrete and reproducible.

The **final player challenge should not expose the root cause this directly**. After proposal approval, the player-facing version should separate verification, identity resolution, authorization data, cache lifecycle, middleware, and route behavior across realistic code paths. Hidden tests should exercise issuer, tenant, assurance, delegation, authorization version, revocation/order permutations, and legitimate cache reuse so a literal one-line or account-specific patch does not pass.
