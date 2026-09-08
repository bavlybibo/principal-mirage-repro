import { signLocalJwt } from "./jwt.js";
import type { JwtClaims } from "./types.js";

export function token(
  overrides: Partial<JwtClaims> & Pick<JwtClaims, "iss" | "sub" | "tenant" | "role" | "acr" | "authzVersion">
): string {
  return signLocalJwt({ delegated: false, ...overrides });
}

export const demo = {
  crossIssuer: {
    corpAdmin: () => token({ iss: "corp-idp", sub: "1847", tenant: "acme", role: "admin", acr: "mfa", authzVersion: 8 }),
    partnerViewer: () => token({ iss: "partner-idp", sub: "1847", tenant: "acme", role: "viewer", acr: "password", authzVersion: 3 })
  },
  crossTenant: {
    acmeAdmin: () => token({ iss: "corp-idp", sub: "user123", tenant: "acme", role: "admin", acr: "mfa", authzVersion: 4 }),
    globexViewer: () => token({ iss: "corp-idp", sub: "user123", tenant: "globex", role: "viewer", acr: "mfa", authzVersion: 2 })
  },
  assurance: {
    mfaAdmin: () => token({ iss: "corp-idp", sub: "alice", tenant: "acme", role: "admin", acr: "mfa", authzVersion: 11 }),
    passwordAdmin: () => token({ iss: "corp-idp", sub: "alice", tenant: "acme", role: "admin", acr: "password", authzVersion: 11 })
  },
  delegation: {
    delegatedSupport: () => token({
      iss: "corp-idp",
      sub: "carol",
      tenant: "acme",
      role: "admin",
      acr: "mfa",
      delegated: true,
      actor: "support-agent",
      authzVersion: 21
    }),
    directViewer: () => token({
      iss: "corp-idp",
      sub: "carol",
      tenant: "acme",
      role: "viewer",
      acr: "mfa",
      delegated: false,
      authzVersion: 21
    })
  },
  revocation: {
    before: () => token({ iss: "corp-idp", sub: "bob", tenant: "acme", role: "admin", acr: "mfa", authzVersion: 17 }),
    after: () => token({ iss: "corp-idp", sub: "bob", tenant: "acme", role: "user", acr: "mfa", authzVersion: 18 })
  }
};

export function reviewerTokenBundle(): Record<string, string> {
  return {
    corpAdmin: demo.crossIssuer.corpAdmin(),
    partnerViewer: demo.crossIssuer.partnerViewer(),
    acmeAdmin: demo.crossTenant.acmeAdmin(),
    globexViewer: demo.crossTenant.globexViewer(),
    mfaAdmin: demo.assurance.mfaAdmin(),
    passwordAdmin: demo.assurance.passwordAdmin(),
    delegatedSupport: demo.delegation.delegatedSupport(),
    directViewer: demo.delegation.directViewer(),
    beforeRevocation: demo.revocation.before(),
    afterRevocation: demo.revocation.after()
  };
}
