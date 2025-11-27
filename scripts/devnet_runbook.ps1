Param(
  [string]$RpcUrl = "https://api.devnet.solana.com",
  [string]$WsUrl = "wss://api.devnet.solana.com",
  [string]$ChainId = "103",
  [string]$DatabaseUrl = "postgres://postgres:postgres@localhost:5432/zksl",
  [string]$AggregatorKeyPath = "./keys/aggregator.json",
  [string]$ProgramName = "validator_lock"
)

$ErrorActionPreference = "Stop"

# Load versions.env if present and verify tool versions
$versions = Join-Path $PSScriptRoot "versions.env"
if (Test-Path $versions) {
  Get-Content $versions | Where-Object { $_ -match '^\s*[^#].+=.+' } | ForEach-Object {
    $kv = $_ -split '=',2
    if ($kv.Length -eq 2) {
      $name = $kv[0].Trim()
      $value = $kv[1].Trim()
      [Environment]::SetEnvironmentVariable($name, $value)
    }
  }
  Write-Host "[zksl][devnet] Expected versions: Solana=$($env:SOLANA_VERSION) Anchor=$($env:ANCHOR_CLI_VERSION)"
}

function Require($cmd) {
  if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
    Write-Error "Missing required tool: $cmd"; exit 1
  }
}

Require solana
Require anchor

Write-Host "[zksl][devnet] Setting Solana RPC: $RpcUrl"
solana config set --url $RpcUrl | Out-Null

if (-not $env:HOME) { $env:HOME = $env:USERPROFILE }
if (-not $env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR = Join-Path $env:USERPROFILE "t" }

Write-Host "[zksl][devnet] Preparing Cargo lockfiles for Solana toolchain"
if (Test-Path "programs/$ProgramName/Cargo.lock") {
  Remove-Item -Force "programs/$ProgramName/Cargo.lock"
}

Push-Location "programs/$ProgramName"
Write-Host "[zksl][devnet] Generating Cargo.lock (v3) with Solana toolchain"
cargo +solana generate-lockfile
Write-Host "[zksl][devnet] Pinning transitive crates for Solana MSRV"
cargo +solana update -p proc-macro-crate@3.4.0 --precise 3.2.0
cargo +solana update -p indexmap --precise 2.11.4
cargo +solana update -p toml_edit --precise 0.22.27
Pop-Location

Write-Host "[zksl][devnet] Ensuring program keypair and deriving Program ID"
$keyPath = "target/deploy/$ProgramName-keypair.json"
if (-not (Test-Path "target/deploy")) { New-Item -ItemType Directory -Force -Path "target/deploy" | Out-Null }
if (-not (Test-Path $keyPath)) {
  solana-keygen new --no-bip39-passphrase -f -o $keyPath | Out-Null
}
$progId = (solana-keygen pubkey $keyPath)
if (-not $progId) { Write-Error "Unable to derive program id from $keyPath"; exit 1 }
Write-Host "[zksl][devnet] Program ID: $progId"

Write-Host "[zksl][devnet] Building Anchor program (skip IDL) with PROGRAM_ID_VALIDATOR_LOCK"
$env:PROGRAM_ID_VALIDATOR_LOCK = $progId
$env:PROGRAM_ID = $progId
anchor build --no-idl

Write-Host "[zksl][devnet] Deploying program to Devnet"
anchor deploy --provider.cluster devnet --program-name $ProgramName --program-keypair $keyPath

Write-Host "[zksl][devnet] Ensuring aggregator key at $AggregatorKeyPath"
node scripts/gen_aggregator_key.js $AggregatorKeyPath

Write-Host "[zksl][devnet] Writing .env"
$envPath = ".env"
$envLines = @(
  "RPC_URL=$RpcUrl",
  "WS_URL=$WsUrl",
  "PROGRAM_ID_VALIDATOR_LOCK=$progId",
  "CHAIN_ID=$ChainId",
  "MIN_FINALITY_COMMITMENT=finalized",
  "AGGREGATOR_KEYPAIR_PATH=$AggregatorKeyPath",
  "ARTIFACT_DIR=./orchestrator/data/artifacts",
  "DATABASE_URL=$DatabaseUrl",
  "PORT=8080",
  "TZ=UTC",
  "LC_ALL=C",
  "LANG=C"
)
Set-Content -Path $envPath -Value ($envLines -join "`n")

Write-Host "[zksl][devnet] Apply database migrations"
if (Get-Command psql -ErrorAction SilentlyContinue) {
  & scripts/db_migrate.sh
} else {
  Write-Warning "psql not found, skip migrations"
}

Write-Host "[zksl][devnet] Devnet program deployed and environment prepared."
Write-Host "[zksl][devnet] Next steps:"
Write-Host "  1) Initialize config: npx tsx cli/src/main.ts init-config --keypair <PAYER.json> --mint <ZKSL_MINT> --agg-key $AggregatorKeyPath --chain-id $ChainId"
Write-Host "  2) Register validator: npx tsx cli/src/main.ts register --keypair <VALIDATOR.json> --mint <ZKSL_MINT>"
Write-Host "  3) Start orchestrator and indexer with Devnet .env and anchor a proof via /prove + /anchor"


