import { createAtlasGateHttpServer } from "./http-server.js";
import { reviewerTokenBundle } from "./fixtures.js";
const modeArg = process.argv[2] ?? "vulnerable";
if (modeArg !== "vulnerable" && modeArg !== "fixed") {
    throw new Error("Usage: node dist/server.js [vulnerable|fixed]");
}
const mode = modeArg;
const host = "127.0.0.1";
const port = 31337;
const server = createAtlasGateHttpServer(mode);
server.listen(port, host, () => {
    console.log(`AtlasGate reviewer server (${mode}) listening on http://${host}:${port}`);
    console.log("Local-only demo tokens follow. Use Authorization: Bearer <token>.");
    console.log(JSON.stringify(reviewerTokenBundle(), null, 2));
});
