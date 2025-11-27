#!/usr/bin/env node

const fetch = require("node-fetch");
const fs = require("fs");
const path = require("path");
const { Connection, PublicKey } = require("@solana/web3.js");

// Load environment
require("dotenv").config({ path: path.join(__dirname, "..", ".env") });

const ORCHESTRATOR_URL =
  process.env.ORCHESTRATOR_URL || "http://localhost:8080";
const RPC_URL = process.env.RPC_URL || "https://api.devnet.solana.com";
const PROGRAM_ID = process.env.PROGRAM_ID_VALIDATOR_LOCK;

async function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function testHealth() {
  console.log("\n1. Testing orchestrator health...");
  try {
    const res = await fetch(`${ORCHESTRATOR_URL}/health`);
    const data = await res.json();
    console.log("   Health check:", data);
    if (data.status !== "ok") {
      throw new Error("Health check failed");
    }
    console.log("   ✓ Orchestrator is healthy");
  } catch (error) {
    console.error("   ✗ Health check failed:", error.message);
    throw error;
  }
}

async function createArtifact() {
  console.log("\n2. Creating artifact...");
  const artifact = {
    start_slot: 1,
    end_slot: 100,
    state_root_before:
      "0000000000000000000000000000000000000000000000000000000000000000",
    state_root_after:
      "1111111111111111111111111111111111111111111111111111111111111111",
  };

  try {
    const res = await fetch(`${ORCHESTRATOR_URL}/artifact`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Idempotency-Key": `test-artifact-${Date.now()}`,
      },
      body: JSON.stringify(artifact),
    });

    if (!res.ok) {
      const error = await res.text();
      throw new Error(`HTTP ${res.status}: ${error}`);
    }

    const data = await res.json();
    console.log("   Artifact created:");
    console.log("   - ID:", data.artifact_id);
    console.log("   - Hash:", data.proof_hash);
    console.log("   ✓ Artifact created successfully");
    return data.artifact_id;
  } catch (error) {
    console.error("   ✗ Failed to create artifact:", error.message);
    throw error;
  }
}

async function anchorProof(artifactId) {
  console.log("\n3. Anchoring proof on-chain...");
  try {
    const res = await fetch(`${ORCHESTRATOR_URL}/anchor`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Idempotency-Key": `test-anchor-${Date.now()}`,
      },
      body: JSON.stringify({ artifact_id: artifactId }),
    });

    if (!res.ok) {
      const error = await res.text();
      throw new Error(`HTTP ${res.status}: ${error}`);
    }

    const data = await res.json();
    console.log("   Anchor response:");
    console.log("   - Transaction:", data.transaction_id);
    console.log("   - DS Hash:", data.ds_hash);

    // Check if it's a local transaction (not on-chain)
    if (data.transaction_id.startsWith("LOCAL-")) {
      console.log("   ⚠ Transaction is LOCAL (not submitted to Devnet)");
      console.log("   This means the orchestrator is running in LOCAL_MODE");
      return null;
    }

    console.log("   ✓ Proof anchored successfully");
    return data.transaction_id;
  } catch (error) {
    console.error("   ✗ Failed to anchor proof:", error.message);
    throw error;
  }
}

async function verifyOnChain(txId) {
  if (!txId) {
    console.log("\n4. Skipping on-chain verification (LOCAL mode)");
    return;
  }

  console.log("\n4. Verifying on-chain transaction...");
  const connection = new Connection(RPC_URL, "confirmed");

  try {
    console.log("   Waiting for confirmation...");
    await sleep(5000); // Wait for transaction to be processed

    const result = await connection.getTransaction(txId, {
      commitment: "confirmed",
      maxSupportedTransactionVersion: 0,
    });

    if (!result) {
      throw new Error("Transaction not found");
    }

    console.log("   Transaction confirmed:");
    console.log("   - Slot:", result.slot);
    console.log(
      "   - Block time:",
      new Date(result.blockTime * 1000).toISOString()
    );
    console.log("   - Fee:", result.meta.fee, "lamports");

    if (result.meta.err) {
      throw new Error(`Transaction failed: ${JSON.stringify(result.meta.err)}`);
    }

    console.log("   ✓ On-chain verification successful");
  } catch (error) {
    console.error("   ✗ On-chain verification failed:", error.message);
    throw error;
  }
}

async function queryProof(artifactId) {
  console.log("\n5. Querying proof status...");
  try {
    const res = await fetch(`${ORCHESTRATOR_URL}/proof/${artifactId}`);

    if (!res.ok) {
      const error = await res.text();
      throw new Error(`HTTP ${res.status}: ${error}`);
    }

    const data = await res.json();
    console.log("   Proof status:");
    if (data.status) {
      console.log("   - Commitment level:", data.status.commitment_level);
      console.log("   - Sequence:", data.status.seq);
      console.log("   - Transaction:", data.status.txid);
    } else {
      console.log("   - Not yet indexed");
    }
    console.log("   ✓ Query successful");
  } catch (error) {
    console.error("   ✗ Query failed:", error.message);
  }
}

async function main() {
  console.log("=== zkSealevel Devnet Test Suite ===");
  console.log("Orchestrator URL:", ORCHESTRATOR_URL);
  console.log("RPC URL:", RPC_URL);
  console.log("Program ID:", PROGRAM_ID);

  if (!PROGRAM_ID) {
    console.error("\nError: PROGRAM_ID_VALIDATOR_LOCK not set in .env");
    process.exit(1);
  }

  try {
    // Test orchestrator health
    await testHealth();

    // Create artifact
    const artifactId = await createArtifact();

    // Anchor proof
    const txId = await anchorProof(artifactId);

    // Verify on-chain
    await verifyOnChain(txId);

    // Query proof status
    await sleep(2000); // Give indexer time to process
    await queryProof(artifactId);

    console.log("\n=== All tests passed! ===");
  } catch (error) {
    console.error("\n=== Test suite failed ===");
    console.error(error);
    process.exit(1);
  }
}

// Handle missing node-fetch
if (typeof fetch === "undefined") {
  global.fetch = require("node-fetch");
}

main().catch(console.error);
