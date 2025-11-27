Param(
  [string]$ProgramName = "validator_lock",
  [string]$Cluster = "devnet"
)

$ErrorActionPreference = "Stop"

# Load versions.env if present
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
}
$anchorVer = $env:ANCHOR_CLI_VERSION; if (-not $anchorVer) { $anchorVer = "0.32.1" }

function Exec($cmd) {
  Write-Host "[zksl][docker] $cmd"
  iex $cmd
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  Write-Error "Docker is required. Please install Docker Desktop."; exit 1
}

Exec "docker build -t zksl-anchor:$anchorVer -f docker/anchor.Dockerfile ."

# Mount workspace and Solana config into the container and run build+deploy
$Work = (Get-Location).Path
$SolCfg = Join-Path $env:USERPROFILE ".config\solana"


$DockerRun = @(
  "docker run --rm",
  "-v `"$Work`":/work",
  (Test-Path $SolCfg ? "-v `"$SolCfg`":/root/.config/solana" : ""),
  "-w /work",
  ("zksl-anchor:{0}" -f $anchorVer),
  "bash -lc 'chmod +x scripts/devnet_docker_deploy.sh && scripts/devnet_docker_deploy.sh " + $ProgramName + " " + $Cluster + "'"
) -join ' '

Exec $DockerRun

Write-Host "[zksl][docker] Deploy completed. Update your .env PROGRAM_ID_VALIDATOR_LOCK with the printed pubkey if needed."


