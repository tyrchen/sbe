const fs = require("fs");
const path = require("path");

const keyPath = path.join(process.env.HOME, ".ssh", "id_ed25519");
try {
  fs.readFileSync(keyPath, "utf8");
  console.error("🚨 shit! private key is being read");
  process.exit(1);
} catch (e) {
  console.error(`🛡️ safe! private key access is blocked: ${e.message}`);
  process.exit(1);
}
