export type Assurance = "password" | "mfa";
export type Role = "viewer" | "user" | "admin";
export type ResolverMode = "vulnerable" | "fixed";

export interface JwtClaims {
  iss: string;
  sub: string;
  aud: string;
  exp: number;
  tenant: string;
  role: Role;
  acr: Assurance;
  delegated?: boolean;
  actor?: string;
  authzVersion: number;
}

export interface Principal {
  issuer: string;
  subject: string;
  tenant: string;
  role: Role;
  assurance: Assurance;
  delegated: boolean;
  actor?: string;
  authzVersion: number;
}

export interface ResolutionResult {
  claims: JwtClaims;
  principal: Principal;
  cacheHit: boolean;
  cacheKey: string;
}

export interface ApiResponse<T = unknown> {
  status: number;
  body: T;
  resolution?: ResolutionResult;
}
