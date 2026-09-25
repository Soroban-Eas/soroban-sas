#!/usr/bin/env bash
set -euo pipefail

# Mocks `stellar` CLI to intercept calls and check for raw secret keys in argv.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

export MOCK_STELLAR_BIN_DIR="$REPO_ROOT/.tmp-mock-bin"
mkdir -p "$MOCK_STELLAR_BIN_DIR"

cat << 'MOCK_EOF' > "$MOCK_STELLAR_BIN_DIR/stellar"
#!/usr/bin/env bash
for arg in "$@"; do
    if [[ "$arg" =~ ^S[A-Z2-7]{55}$ ]]; then
        echo "FAIL: secret key exposed in argv: stellar $@" >&2
        exit 1
    fi
done

# If mock gets `keys add`, it needs to mimic it just enough for script to proceed to deploy
if [[ "$1" == "keys" && "$2" == "add" ]]; then
    exit 0
fi

if [[ "$1" == "keys" && "$2" == "address" ]]; then
    echo "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    exit 0
fi

echo "Mock stellar called with safe args."
exit 1 # We exit 1 so deploy stops early since we aren't outputting a C... contract id
MOCK_EOF

chmod +x "$MOCK_STELLAR_BIN_DIR/stellar"
export PATH="$MOCK_STELLAR_BIN_DIR:$PATH"

# Run deploy with dummy key
DUMMY_KEY="SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
# We expect deploy.sh to fail at some point because our mock doesn't output real contract IDs, 
# but it should not fail due to the argv check in our mock.
OUTPUT=$(./scripts/deploy.sh --secret-key "$DUMMY_KEY" --skip-build 2>&1 || true)

rm -rf "$MOCK_STELLAR_BIN_DIR"

if echo "$OUTPUT" | grep -q "FAIL: secret key exposed in argv"; then
    echo "Test Failed: Secret key leaked to argv"
    echo "$OUTPUT"
    exit 1
else
    echo "Test Passed: No secret key in argv"
    exit 0
fi
