#!/usr/bin/env node

const {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
} = require("@solana/web3.js");
const { Program, AnchorProvider, web3, BN } = require("@coral-xyz/anchor");
const fs = require("fs");
const path = require("path");
const nacl = require("tweetnacl");

// Load environment variables
require("dotenv").config({ path: path.join(__dirname, "..", ".env") });

const RPC_URL = process.env.RPC_URL || "https://api.devnet.solana.com";
const PROGRAM_ID = process.env.PROGRAM_ID_VALIDATOR_LOCK;
const CHAIN_ID = 103; // Devnet

async function main() {
  console.log("=== Initializing zkSealevel on Devnet ===");
  console.log("RPC URL:", RPC_URL);
  console.log("Program ID:", PROGRAM_ID);
  console.log("");

  if (!PROGRAM_ID) {
    console.error("Error: PROGRAM_ID_VALIDATOR_LOCK not set in .env");
    process.exit(1);
  }

  // Load wallet
  const walletPath = path.join(
    process.env.HOME || process.env.USERPROFILE,
    ".config",
    "solana",
    "id.json"
  );
  if (!fs.existsSync(walletPath)) {
    console.error("Error: Wallet not found at", walletPath);
    console.error("Run: solana-keygen new");
    process.exit(1);
  }

  const wallet = Keypair.fromSecretKey(
    new Uint8Array(JSON.parse(fs.readFileSync(walletPath, "utf-8")))
  );
  console.log("Admin wallet:", wallet.publicKey.toBase58());

  // Create or load aggregator keypair
  const aggPath = path.join(__dirname, "..", "keys", "aggregator.json");
  let aggregatorKeypair;

  if (!fs.existsSync(aggPath)) {
    console.log("Creating new aggregator keypair...");
    fs.mkdirSync(path.dirname(aggPath), { recursive: true });

    const kp = nacl.sign.keyPair();
    fs.writeFileSync(
      aggPath,
      JSON.stringify({
        secretKey: Buffer.from(kp.secretKey).toString("hex"),
      })
    );
    aggregatorKeypair = kp;
  } else {
    console.log("Loading existing aggregator keypair...");
    const aggData = JSON.parse(fs.readFileSync(aggPath, "utf-8"));
    const secretKey = Buffer.from(aggData.secretKey, "hex");
    aggregatorKeypair = nacl.sign.keyPair.fromSecretKey(secretKey);
  }

  const aggregatorPubkey = new PublicKey(aggregatorKeypair.publicKey);
  console.log("Aggregator pubkey:", aggregatorPubkey.toBase58());

  // Connect to cluster
  const connection = new Connection(RPC_URL, "confirmed");
  const provider = new AnchorProvider(connection, wallet, {
    commitment: "confirmed",
  });

  // Load IDL
  const idlPath = path.join(
    __dirname,
    "..",
    "target",
    "idl",
    "validator_lock.json"
  );
  if (!fs.existsSync(idlPath)) {
    console.error("Error: IDL not found. Run 'anchor build' first");
    process.exit(1);
  }
  const idl = JSON.parse(fs.readFileSync(idlPath, "utf-8"));

  const program = new Program(idl, PROGRAM_ID, provider);

  // Derive PDAs
  const [configPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("zksl"), Buffer.from("config")],
    program.programId
  );

  const [aggregatorStatePda] = PublicKey.findProgramAddressSync(
    [Buffer.from("zksl"), Buffer.from("aggregator")],
    program.programId
  );

  const [rangeStatePda] = PublicKey.findProgramAddressSync(
    [Buffer.from("zksl"), Buffer.from("range")],
    program.programId
  );

  console.log("\nPDAs:");
  console.log("Config:", configPda.toBase58());
  console.log("AggregatorState:", aggregatorStatePda.toBase58());
  console.log("RangeState:", rangeStatePda.toBase58());

  // Check if already initialized
  try {
    const configAccount = await program.account.config.fetch(configPda);
    console.log("\nConfig already initialized:");
    console.log("- Admin:", configAccount.admin.toBase58());
    console.log("- Aggregator:", configAccount.aggregatorPubkey.toBase58());
    console.log("- Chain ID:", configAccount.chainId.toString());
    console.log("- Paused:", configAccount.paused);

    // Initialize aggregator and range state if needed
    try {
      await program.account.aggregatorState.fetch(aggregatorStatePda);
      console.log("AggregatorState already initialized");
    } catch (e) {
      console.log("\nInitializing AggregatorState and RangeState...");
      const tx = await program.methods
        .initState()
        .accounts({
          config: configPda,
          aggregatorState: aggregatorStatePda,
          rangeState: rangeStatePda,
          payer: wallet.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
      console.log("Init state tx:", tx);
    }

    return;
  } catch (e) {
    // Config not initialized, proceed
  }

  // Create a dummy SPL token mint for testing (in production, use real token)
  console.log("\nUsing System Program as dummy mint (for testing only)");
  const dummyMint = SystemProgram.programId;

  // Initialize config
  console.log("\nInitializing config...");
  try {
    const tx = await program.methods
      .initialize({
        aggregatorPubkey: aggregatorPubkey,
        nextAggregatorPubkey: aggregatorPubkey,
        activationSeq: new BN(1),
        chainId: new BN(CHAIN_ID),
      })
      .accounts({
        config: configPda,
        zkslMint: dummyMint,
        admin: wallet.publicKey,
        payer: wallet.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    console.log("Initialize tx:", tx);
    console.log("Config initialized successfully!");
  } catch (error) {
    console.error("Failed to initialize:", error);
    process.exit(1);
  }

  // Initialize aggregator and range state
  console.log("\nInitializing AggregatorState and RangeState...");
  try {
    const tx = await program.methods
      .initState()
      .accounts({
        config: configPda,
        aggregatorState: aggregatorStatePda,
        rangeState: rangeStatePda,
        payer: wallet.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    console.log("Init state tx:", tx);
    console.log("States initialized successfully!");
  } catch (error) {
    console.error("Failed to initialize states:", error);
    process.exit(1);
  }

  // Verify initialization
  const configAccount = await program.account.config.fetch(configPda);
  const aggState = await program.account.aggregatorState.fetch(
    aggregatorStatePda
  );
  const rangeState = await program.account.rangeState.fetch(rangeStatePda);

  console.log("\n=== Initialization Complete ===");
  console.log("Config:");
  console.log("- Admin:", configAccount.admin.toBase58());
  console.log("- Aggregator:", configAccount.aggregatorPubkey.toBase58());
  console.log("- Chain ID:", configAccount.chainId.toString());
  console.log("- Activation Seq:", configAccount.activationSeq.toString());
  console.log("\nAggregatorState:");
  console.log("- Last Seq:", aggState.lastSeq.toString());
  console.log("\nRangeState:");
  console.log("- Last End Slot:", rangeState.lastEndSlot.toString());
}

main().catch(console.error);
