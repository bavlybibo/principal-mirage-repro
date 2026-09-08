import { createServer } from "node:http";
import { AtlasGateApp } from "./app.js";
function bearer(req) {
    const value = req.headers.authorization;
    if (!value?.startsWith("Bearer ")) return undefined;
    return value.slice("Bearer ".length);
}
function writeJson(res, status, body) {
    const data = JSON.stringify(body, null, 2);
    res.statusCode = status;
    res.setHeader("content-type", "application/json; charset=utf-8");
    res.setHeader("content-length", Buffer.byteLength(data));
    res.end(data);
}
export function createAtlasGateHttpServer(mode) {
    const app = new AtlasGateApp(mode);
    return createServer((req, res) => {
        const method = req.method ?? "GET";
        const path = new URL(req.url ?? "/", "http://127.0.0.1").pathname;
        const response = app.handle(method, path, bearer(req));
        writeJson(res, response.status, response.body);
    });
}
