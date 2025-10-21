#!/usr/bin/env bash
set -euo pipefail

echo "Test runner starting..."

CA_CERT="/certs/ca.crt"
PROBE_BIN="/workspace/test/bin/probe_client"
SERVER_ADDR="vnt-control:4242"

if [ ! -f "$CA_CERT" ]; then
  echo "CA certificate not found at $CA_CERT. Did you generate certs?"
  echo "Run: ./test/generate-certs.sh"
  exit 1
fi

if [ -x "$PROBE_BIN" ]; then
  echo "Found probe binary: $PROBE_BIN"
  echo "Waiting for server readiness..."
  for i in $(seq 1 20); do
    if "$PROBE_BIN" --server="$SERVER_ADDR" --ca="$CA_CERT" --probe; then
      echo "server ready"
      break
    fi
    echo "not ready yet ($i/20)"
    sleep 1
  done

  echo "Running full test..."
  "$PROBE_BIN" --server="$SERVER_ADDR" --ca="$CA_CERT" --run-test
  exit $?
else
  echo "No probe binary found at $PROBE_BIN. Please provide a Rust probe client or replace tester image with one that contains your client." 
  echo "Expected probe binary path inside container: $PROBE_BIN"
  echo "You can build a simple quinn-based probe that accepts --server and --ca parameters and place it at test/bin/probe_client"
  exit 2
fi
