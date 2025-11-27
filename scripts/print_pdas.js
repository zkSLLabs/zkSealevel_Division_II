#!/usr/bin/env node
const web3 = require("@solana/web3.js");
const pidStr = process.env.PROGRAM_ID_VALIDATOR_LOCK;
if (!pidStr) {
  console.error("PROGRAM_ID_VALIDATOR_LOCK is required");
  process.exit(1);
}
const programId = new web3.PublicKey(pidStr);
const [configPda] = web3.PublicKey.findProgramAddressSync(
  [Buffer.from("zksl"), Buffer.from("config")],
  programId
);
const [aggregatorStatePda] = web3.PublicKey.findProgramAddressSync(
  [Buffer.from("zksl"), Buffer.from("aggregator")],
  programId
);
const [rangeStatePda] = web3.PublicKey.findProgramAddressSync(
  [Buffer.from("zksl"), Buffer.from("range")],
  programId
);
console.log(
  JSON.stringify(
    {
      configPda: configPda.toBase58(),
      aggregatorStatePda: aggregatorStatePda.toBase58(),
      rangeStatePda: rangeStatePda.toBase58(),
    },
    null,
    2
  )
);
