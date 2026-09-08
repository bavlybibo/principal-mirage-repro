# Principal Mirage — Proposal Repost Note

Thanks for the feedback. I have now implemented a self-contained working reproduction of the vulnerability described in **Principal Mirage**.

The attached TypeScript/Node.js sample demonstrates that independently valid, correctly signed JWTs can receive authorization state belonging to a different authenticated security context because the application caches a resolved security principal using an incomplete identity equivalence key.

The reproduction now exercises the issue end-to-end through an AtlasGate application/policy layer and covers five independent security-context boundaries:

1. cross-issuer identity isolation;
2. cross-tenant authorization isolation;
3. authentication assurance / MFA isolation;
4. delegated vs. direct authorization context isolation;
5. authorization-version / stale privilege isolation.

It also includes request-order regression coverage, legitimate same-context cache reuse, and a parallel reference-fixed resolver so the reviewer can confirm the five exploit chains are caused by the cache-equivalence bug rather than invalid JWT handling or intentionally broken policy rules.

No forged token, invalid signature, algorithm confusion, invalid audience, expired credential, brute force, or external infrastructure is involved. Every demonstrated credential is locally signed by a trusted simulated issuer and independently cryptographically verified before the principal cache is consulted.

## Fastest reproduction

With Node.js 20+:

```bash
node dist/repro.js
```

Expected final line:

```text
PASS: reproduced 5 end-to-end authorization failures and confirmed the reference fix blocks all 5 chains.
```

The repository also includes compiled JavaScript, full TypeScript source, vulnerable/fixed regression suites, an optional localhost HTTP server, `REPRO-OUTPUT.txt`, and `TEST-OUTPUT.txt`.

This repository is intentionally transparent as a **proposal-review reproduction**. The eventual SecDim Play player challenge would keep the same architectural security invariant but make discovery materially harder through realistic code separation and hidden adversarial regression tests rather than exposing the root cause directly.
