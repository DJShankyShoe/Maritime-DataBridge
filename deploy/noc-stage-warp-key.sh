#!/usr/bin/env bash
# Copies the WARP private signing key for the vessel daemon.

# Runs once at service startup as root, reads Cloudflare WARP's reg.json, extracts
# the P-256 private key (ignoring API tokens and other fields), and writes it as
# raw PKCS#8 DER to /run/noc-vessel/warp_identity.key (mode 0400, owned by noc-vessel).
# This lets the daemon read its identity key while running unprivileged with zero capabilities.
# Note: If keys are rotated via `warp-cli registration rotate-keys`, restart the service to re-stage.
set -euo pipefail

REG="${WARP_REG:-/var/lib/cloudflare-warp/reg.json}"
OUT="${NOC_VESSEL_KEY:-/run/noc-vessel/warp_identity.key}"
USER_GROUP="${NOC_VESSEL_USER:-noc-vessel}:${NOC_VESSEL_GROUP:-noc-vessel}"

# If no WARP registration exists (common in dev/test setups), skip staging so the daemon can start.
if [ ! -f "$REG" ]; then
  echo "no WARP reg.json at $REG; skipping WARP key staging (dev/test key path)"
  exit 0
fi

# On the WireGuard tunnel protocol WARP stores a 32-byte X25519 key instead of a P-256
# one. If we staged that, the daemon would later fail with a confusing "malformed public
# key" error. So we check it is really a P-256 key first, and stage nothing if it is not.
if ! python3 - "$REG" "$OUT" <<'PY'
import json, sys, base64
reg = json.load(open(sys.argv[1]))
der = base64.b64decode(reg["secret_key"])
# PKCS#8 PrivateKeyInfo: SEQUENCE, carrying the prime256v1 OID (1.2.840.10045.3.1.7).
if len(der) < 64 or der[0] != 0x30 or bytes.fromhex("2a8648ce3d030107") not in der:
    print(f"    reg.json secret_key is {len(der)} bytes and is not a PKCS#8 P-256 key",
          file=sys.stderr)
    sys.exit(1)
open(sys.argv[2], "wb").write(der)
PY
then
  echo "not staging a WARP identity key: this registration does not hold a P-256 key." >&2
  echo "Point [identity] key_file at a separately provisioned PKCS#8 P-256 key, and" >&2
  echo "enrol its public key (base64 SPKI) on shore in devices.toml." >&2
  exit 0
fi

chown "$USER_GROUP" "$OUT"
chmod 0400 "$OUT"
echo "staged WARP identity key -> $OUT"
