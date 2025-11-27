/* Generate a valid Ed25519 keypair for aggregator into keys/aggregator.json */
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const nacl = require("tweetnacl");
const out =
  process.argv[2] ||
  process.env.AGGREGATOR_KEYPAIR_PATH ||
  path.join("keys", "aggregator.json");
fs.mkdirSync(path.dirname(out), { recursive: true });
const seed = crypto.randomBytes(32);
const kp = nacl.sign.keyPair.fromSeed(seed);
const secretHex = Buffer.from(kp.secretKey).toString("hex"); // 64 bytes
const publicHex = Buffer.from(kp.publicKey).toString("hex"); // 32 bytes
fs.writeFileSync(
  out,
  JSON.stringify({ secretKey: secretHex, publicKey: publicHex }, null, 2)
);
console.log(`[zksl] wrote aggregator key to ${out}`);
