#!/bin/bash
# DTLS STUN server scanner using wolfSSL
#
# - Fetches public STUN server list
# - Tests DTLS 1.2 (each ECDHE-ECDSA-* cipher individually) and DTLS 1.3
# - All cipher probes + cert verification run in parallel
# - Certificate trust verified via wolfSSL (no openssl dependency)
#
# Requires: WOLFSSL_HOME env var

set -euo pipefail

HOST_LIST_URL="https://raw.githubusercontent.com/pradt2/always-online-stun/refs/heads/master/valid_hosts.txt"
PORT=5349
TIMEOUT=6
ATTEMPTS=3
PARALLEL=20

ECDSA_CIPHERS_12=(
  ECDHE-ECDSA-AES128-GCM-SHA256
  ECDHE-ECDSA-AES256-GCM-SHA384
  ECDHE-ECDSA-CHACHA20-POLY1305
  ECDHE-ECDSA-AES128-SHA256
  ECDHE-ECDSA-AES256-SHA384
  ECDHE-ECDSA-AES128-SHA
  ECDHE-ECDSA-AES256-SHA
)
ALL_ECDSA_12=$(IFS=:; echo "${ECDSA_CIPHERS_12[*]}")

# ── Detect system CA bundle ──────────────────────────────

CA_BUNDLE=""
for p in /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-bundle.crt \
         /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do
  [[ -f "$p" ]] && CA_BUNDLE="$p" && break
done

# ── Resolve wolfSSL client ───────────────────────────────

CLIENT="$WOLFSSL_HOME/build/examples/client/client"

# ── Self-dispatch: --scan-host <host> <result_dir> ───────

if [[ "${1:-}" == "--scan-host" ]]; then
  host=$2
  result_dir=$3
  CLIENT="$WOLFSSL_HOME/build/examples/client/client"

  # Step 1: quick gate — can this host do DTLS at all?
  probe_out=$(cd "$WOLFSSL_HOME" && timeout "$TIMEOUT" "$CLIENT" \
    -u -v 3 -h "$host" -p "$PORT" -d -x -S "$host" \
    -l "$ALL_ECDSA_12" 2>&1) || true
  if ! echo "$probe_out" | grep -q "SSL version is DTLSv1.2"; then
    probe_out=$(cd "$WOLFSSL_HOME" && timeout "$TIMEOUT" "$CLIENT" \
      -u -v 4 -h "$host" -p "$PORT" -d -x -S "$host" 2>&1) || true
    if ! echo "$probe_out" | grep -q "SSL version is DTLSv1.3"; then
      echo "FAIL $host:$PORT"
      exit 0
    fi
  fi

  # Step 2: parallel probes — all ciphers + DTLS 1.3 + cert verification
  tmpdir=$(mktemp -d)
  trap 'rm -rf "$tmpdir"' EXIT

  # DTLS 1.2: each cipher in parallel
  for cipher in "${ECDSA_CIPHERS_12[@]}"; do
    (
      for _ in $(seq 1 "$ATTEMPTS"); do
        out=$(cd "$WOLFSSL_HOME" && timeout "$TIMEOUT" "$CLIENT" \
          -u -v 3 -h "$host" -p "$PORT" -d -x -S "$host" \
          -l "$cipher" 2>&1) || true
        if echo "$out" | grep -q "SSL version is DTLSv1.2"; then
          echo "$cipher" > "$tmpdir/c12_$cipher"
          break
        fi
      done
    ) &
  done

  # DTLS 1.3 probe
  (
    for _ in $(seq 1 "$ATTEMPTS"); do
      out=$(cd "$WOLFSSL_HOME" && timeout "$TIMEOUT" "$CLIENT" \
        -u -v 4 -h "$host" -p "$PORT" -d -x -S "$host" 2>&1) || true
      if echo "$out" | grep -q "SSL version is DTLSv1.3"; then
        echo "$out" | grep "SSL cipher suite is" | sed 's/.*SSL cipher suite is //' \
          > "$tmpdir/dtls13"
        break
      fi
    done
  ) &

  # Certificate verification via wolfSSL (no -d flag, use -A for CA bundle)
  if [[ -n "$CA_BUNDLE" ]]; then
    (
      out=$(cd "$WOLFSSL_HOME" && timeout "$TIMEOUT" "$CLIENT" \
        -u -v 3 -h "$host" -p "$PORT" -x -S "$host" \
        -A "$CA_BUNDLE" -l "$ALL_ECDSA_12" 2>&1)
      # shellcheck disable=SC2181
      if [[ $? -eq 0 ]] && echo "$out" | grep -q "SSL version is DTLSv1"; then
        echo "TRUSTED" > "$tmpdir/cert_status"
      else
        echo "UNTRUSTED" > "$tmpdir/cert_status"
      fi
    ) &
  fi

  wait

  # Step 3: collect results
  supported_12=()
  for cipher in "${ECDSA_CIPHERS_12[@]}"; do
    [[ -f "$tmpdir/c12_$cipher" ]] && supported_12+=("$cipher")
  done

  dtls13_cipher=""
  [[ -f "$tmpdir/dtls13" ]] && dtls13_cipher=$(cat "$tmpdir/dtls13")

  cert_status="N/A"
  [[ -f "$tmpdir/cert_status" ]] && cert_status=$(cat "$tmpdir/cert_status")

  # Write structured result file
  {
    echo "cert=$cert_status"
    if [[ -n "$dtls13_cipher" ]]; then
      echo "1.3=$dtls13_cipher"
    fi
    for c in "${supported_12[@]}"; do
      echo "1.2=$c"
    done
  } > "$result_dir/$host"
  echo "OK   $host:$PORT  cert=$cert_status  1.2=${#supported_12[@]} ciphers  1.3=${dtls13_cipher:-none}"
  exit 0
fi

# ── Main ─────────────────────────────────────────────────

if [[ -z "${WOLFSSL_HOME:-}" ]]; then
  echo "ERROR: WOLFSSL_HOME is not set"
  echo "Usage: WOLFSSL_HOME=/path/to/wolfssl bash $0"
  exit 1
fi

CLIENT="$WOLFSSL_HOME/build/examples/client/client"
if ! command -v "$CLIENT" &>/dev/null && [[ ! -x "$CLIENT" ]]; then
  echo "ERROR: wolfSSL client binary not found at $CLIENT"
  echo "Build: cd \$WOLFSSL_HOME && cmake -B build -DWOLFSSL_DTLS=yes -DWOLFSSL_DTLS13=yes && cmake --build build"
  exit 1
fi

if [[ -n "$CA_BUNDLE" ]]; then
  echo "CA bundle: $CA_BUNDLE"
else
  echo "WARNING: No system CA bundle found — certificate verification will show N/A"
fi

echo "Fetching STUN server list..."
HOSTS=$(curl -sfL "$HOST_LIST_URL" | sed 's/:.*//')
HOST_COUNT=$(echo "$HOSTS" | wc -l | tr -d ' ')
echo "Got $HOST_COUNT hosts. Scanning port $PORT (ECDHE-ECDSA, ${ATTEMPTS} attempts, ${PARALLEL} parallel)..."
echo ""

RESULT_DIR=$(mktemp -d)
trap 'rm -rf "$RESULT_DIR"' EXIT

echo "$HOSTS" | xargs -P"$PARALLEL" -I{} bash "$0" --scan-host {} "$RESULT_DIR"

# ── Display results ──────────────────────────────────────

echo ""
echo "================================================================================"
echo " DTLS Scan Results — ECDHE-ECDSA, port $PORT, wolfSSL"
echo "================================================================================"
echo ""

OK_COUNT=0
if ls "$RESULT_DIR"/* 1>/dev/null 2>&1; then
  for f in $(ls "$RESULT_DIR"/* 2>/dev/null | sort); do
    host=$(basename "$f")
    cert_status="" dtls13="" dtls12_ciphers=()
    while IFS='=' read -r key val; do
      case "$key" in
        cert)  cert_status="$val" ;;
        1.3)   dtls13="$val" ;;
        1.2)   dtls12_ciphers+=("$val") ;;
      esac
    done < "$f"

    echo "  $host:$PORT"
    echo "    Cert:     $cert_status"
    if [[ ${#dtls12_ciphers[@]} -gt 0 ]]; then
      echo "    DTLS 1.2: ${#dtls12_ciphers[@]} ciphers"
      for c in "${dtls12_ciphers[@]}"; do
        echo "              - $c"
      done
    else
      echo "    DTLS 1.2: not supported"
    fi
    if [[ -n "$dtls13" ]]; then
      echo "    DTLS 1.3: $dtls13"
    else
      echo "    DTLS 1.3: not supported"
    fi
    echo ""
    OK_COUNT=$((OK_COUNT + 1))
  done
fi

echo "Total: $OK_COUNT / $HOST_COUNT servers support DTLS with ECDHE-ECDSA on port $PORT"
echo ""
echo "CERT: TRUSTED = verified against system CA, UNTRUSTED = self-signed/unknown, N/A = no CA bundle"
