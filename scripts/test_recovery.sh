#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

echo "Running deploy manifest tests..."

MANIFEST_FILE=".deploy-manifest.env"
ENV_FILE=".env.test"
export SOROBAN_SECRET_KEY="SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
export SOROBAN_NETWORK_PASSPHRASE="Standalone Network ; February 2017"
export SOROBAN_RPC_URL="http://localhost:8000"

# Cleanup
rm -f "$MANIFEST_FILE" "$ENV_FILE"

# Create a fake mock CLI for stellar that fails intentionally on SAS initialization
cat << 'EOF' > stellar_mock.sh
#!/usr/bin/env bash
if [[ "$*" == *"deploy"* ]]; then
    # return fake id
    echo "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
elif [[ "$*" == *"init"* && "$*" == *"--registry"* ]]; then
    echo "Failing SAS initialization for test" >&2
    exit 1
else
    echo "success"
fi
EOF
chmod +x stellar_mock.sh

# Temporary modify deploy.sh to use our mock CLI
sed -i 's/CLI_BIN=""/CLI_BIN=".\/stellar_mock.sh"/g' scripts/deploy.sh
# Also skip rust build in test
sed -i 's/SKIP_BUILD=false/SKIP_BUILD=true/g' scripts/deploy.sh
# Touch dummy wasms
mkdir -p target/wasm32-unknown-unknown/release
touch target/wasm32-unknown-unknown/release/schema_registry.wasm
touch target/wasm32-unknown-unknown/release/sas.wasm
touch target/wasm32-unknown-unknown/release/soroban_sas_indexer.wasm

echo "Running deployment - should fail at SAS init..."
if scripts/deploy.sh --env-file "$ENV_FILE" --skip-build > /dev/null 2>&1; then
    echo "ERROR: deploy.sh should have failed!"
    exit 1
fi

echo "Checking if manifest exists..."
if [[ ! -f "$MANIFEST_FILE" ]]; then
    echo "ERROR: Manifest file was not created!"
    exit 1
fi

echo "Checking manifest contents..."
if ! grep -q "MANIFEST_REGISTRY_INIT=true" "$MANIFEST_FILE"; then
    echo "ERROR: Manifest did not save REGISTRY_INIT!"
    exit 1
fi
if grep -q "MANIFEST_SAS_INIT=true" "$MANIFEST_FILE"; then
    echo "ERROR: Manifest falsely claims SAS_INIT!"
    exit 1
fi

echo "Fixing mock to succeed..."
cat << 'EOF' > stellar_mock.sh
#!/usr/bin/env bash
if [[ "$*" == *"deploy"* ]]; then
    echo "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
elif [[ "$*" == *"get_indexer"* || "$*" == *"get_sas"* ]]; then
    echo "\"CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\""
else
    echo "success"
fi
EOF

echo "Resuming deployment..."
scripts/deploy.sh --env-file "$ENV_FILE" --skip-build --resume > /dev/null

if [[ -f "$MANIFEST_FILE" ]]; then
    echo "ERROR: Manifest file should be deleted on success!"
    exit 1
fi

if ! grep -q "SCHEMA_REGISTRY_CONTRACT_ID=CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" "$ENV_FILE"; then
    echo "ERROR: Env file not correctly populated!"
    exit 1
fi

# Restore deploy.sh
git checkout scripts/deploy.sh

echo "Tests passed successfully!"
rm -f stellar_mock.sh "$ENV_FILE"
