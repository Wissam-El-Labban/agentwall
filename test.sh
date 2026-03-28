#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME="agentfirewall-test"

echo "==> Building test container..."
docker build -t "$IMAGE_NAME" .

echo ""
echo "==> Running tests in container..."
docker run --rm \
    --read-only \
    --tmpfs /tmp \
    --network none \
    --security-opt no-new-privileges \
    "$IMAGE_NAME" \
    pytest -v --tb=short "$@"
