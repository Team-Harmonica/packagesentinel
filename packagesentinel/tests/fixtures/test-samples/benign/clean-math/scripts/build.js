// Dev-only build script: running the TypeScript compiler is normal.
const { execSync } = require("child_process");

execSync("tsc -p .", { stdio: "inherit" });
