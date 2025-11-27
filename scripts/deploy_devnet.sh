#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

echo "=== zkSealevel Devnet Deployment Script ==="
echo "This script will build and deploy the validator_lock program to Solana Devnet"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running in WSL or Linux
if [[ ! -f /proc/version ]] || ([[ ! $(grep -i microsoft /proc/version) ]] && [[ ! $(uname -s) == "Linux" ]]); then
    echo -e "${RED}Error: This script must be run in WSL2 or Linux${NC}"
    exit 1
fi

# Function to check command exists
check_command() {
    if ! command -v $1 &> /dev/null; then
        echo -e "${RED}Error: $1 is not installed${NC}"
        return 1
    fi
    return 0
}

# Load central versions if available
if [ -f "$(dirname "$0")/versions.env" ]; then
  # shellcheck disable=SC1091
  . "$(dirname "$0")/versions.env"
fi
ANCHOR_CLI_VERSION="${ANCHOR_CLI_VERSION:-0.32.1}"
SOLANA_VERSION="${SOLANA_VERSION:-v2.1.15}"
NODE_MAJOR="${NODE_MAJOR:-22}"

# Function to install dependencies
install_deps() {
    echo -e "${YELLOW}Installing dependencies...${NC}"
    
    # Update package list
    sudo apt-get update -qq
    
    # Install basic tools
    sudo apt-get install -y -qq curl build-essential pkg-config libssl-dev
    
    # Install Rust if not present
    if ! check_command rustc; then
        echo "Installing Rust..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
    fi
    
    # Install Solana if not present
    if ! check_command solana; then
        echo "Installing Solana CLI ${SOLANA_VERSION}..."
        sh -c "$(curl -sSfL https://release.solana.com/${SOLANA_VERSION}/install)"
        export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
        echo 'export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"' >> ~/.bashrc
    fi
    
    # Install Anchor if not present
    if ! check_command anchor; then
        echo "Installing Anchor ${ANCHOR_CLI_VERSION}..."
        cargo install --git https://github.com/coral-xyz/anchor avm --force
        avm install "${ANCHOR_CLI_VERSION}"
        avm use "${ANCHOR_CLI_VERSION}"
    fi
    
    # Install Node.js if not present
    if ! check_command node; then
        echo "Installing Node.js ${NODE_MAJOR}.x..."
        curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | sudo -E bash -
        sudo apt-get install -y nodejs
    fi
}

# Check and install dependencies
echo -e "${YELLOW}Checking dependencies...${NC}"
install_deps

# Source cargo and solana paths
source "$HOME/.cargo/env" 2>/dev/null || true
export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"

# Verify installations
echo -e "${GREEN}Verifying installations:${NC}"
echo "Rust: $(rustc --version)"
echo "Solana: $(solana --version)"
echo "Anchor: $(anchor --version)"
echo "Node: $(node --version)"
echo ""

# Configure Solana for Devnet
echo -e "${YELLOW}Configuring Solana for Devnet...${NC}"
solana config set --url https://api.devnet.solana.com

# Check or create wallet
WALLET_PATH="$HOME/.config/solana/id.json"
if [ ! -f "$WALLET_PATH" ]; then
    echo -e "${YELLOW}Creating new wallet...${NC}"
    solana-keygen new --no-bip39-passphrase -o "$WALLET_PATH"
fi

echo "Wallet address: $(solana address)"

# Check balance and request airdrop if needed
BALANCE=$(solana balance | awk '{print $1}')
if (( $(echo "$BALANCE < 2" | bc -l) )); then
    echo -e "${YELLOW}Requesting airdrop...${NC}"
    solana airdrop 2 || echo "Airdrop failed (rate limited), continuing with existing balance"
fi
echo "Current balance: $(solana balance)"

# Build the program
echo -e "${YELLOW}Building the validator_lock program...${NC}"
cd programs/validator_lock
anchor build

# Get the program ID
PROGRAM_ID=$(anchor keys list | grep validator_lock | awk '{print $2}')
echo -e "${GREEN}Program ID: $PROGRAM_ID${NC}"

# Deploy to Devnet
echo -e "${YELLOW}Deploying to Devnet...${NC}"
anchor deploy --provider.cluster devnet

# Verify deployment
echo -e "${GREEN}Verifying deployment...${NC}"
solana program show "$PROGRAM_ID" --url devnet

# Update .env file with program ID
cd ../..
if [ -f .env ]; then
    sed -i "s/PROGRAM_ID_VALIDATOR_LOCK=.*/PROGRAM_ID_VALIDATOR_LOCK=$PROGRAM_ID/" .env
else
    echo "PROGRAM_ID_VALIDATOR_LOCK=$PROGRAM_ID" > .env
fi

echo ""
echo -e "${GREEN}=== Deployment Complete ===${NC}"
echo -e "Program ID: ${GREEN}$PROGRAM_ID${NC}"
echo ""
echo "Next steps:"
echo "1. Initialize the on-chain state using the init script"
echo "2. Start the orchestrator and indexer services"
echo "3. Run the test script to verify the deployment"

