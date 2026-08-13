#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

IMAGE="${IICP_INSTANCE_LOCK_IMAGE:-iicp-node-instance-lock-test}"
docker build --quiet -t "$IMAGE" . >/dev/null

docker run --rm --network none --entrypoint /bin/sh \
  -e IICP_AUTO_UPDATE=0 \
  -e IICP_SKIP_REGISTRATION=1 \
  -e IICP_AUTO_DETECT_NAT=0 \
  -e IICP_TUNNEL=0 \
  "$IMAGE" -c '
set -eu
export IICP_HOME=/tmp/iicp-home
mkdir -p "$IICP_HOME"

iicp-node serve --node-id lock-regression --model test-model \
  --backend-url http://127.0.0.1:9 --host 127.0.0.1 --port 8020 \
  >/tmp/first.out 2>/tmp/first.err &
first=$!
trap '\''kill "$first" 2>/dev/null || true; wait "$first" 2>/dev/null || true'\'' EXIT
sleep 2
kill -0 "$first"

set +e
iicp-node serve --node-id lock-regression --model test-model \
  --backend-url http://127.0.0.1:9 --host 127.0.0.1 --port 8021 \
  >/tmp/second.out 2>/tmp/second.err
status=$?
set -e

test "$status" -ne 0
grep -q "already being served" /tmp/second.err
kill -0 "$first"
'

echo "supported Docker image rejects a duplicate node instance"
