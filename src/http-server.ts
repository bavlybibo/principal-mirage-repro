import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { AtlasGateApp } from "./app.js";
import type { ResolverMode } from "./types.js";

function bearer(req: IncomingMessage): string | undefined {
  const value = req.headers.authorization;
  if (!value?.startsWith("Bearer ")) return undefined;
  return value.slice("Bearer ".length);
}

function writeJson(res: ServerResponse, status: number, body: unknown): void {
  const data = JSON.stringify(body, null, 2);
  res.statusCode = status;
  res.setHeader("content-type", "application/json; charset=utf-8");
  res.setHeader("content-length", Buffer.byteLength(data));
  res.end(data);
}

export function createAtlasGateHttpServer(mode: ResolverMode) {
  const app = new AtlasGateApp(mode);
  return createServer((req, res) => {
    const method = req.method ?? "GET";
    const path = new URL(req.url ?? "/", "http://127.0.0.1").pathname;
    const response = app.handle(method, path, bearer(req));
    writeJson(res, response.status, response.body);
  });
}
