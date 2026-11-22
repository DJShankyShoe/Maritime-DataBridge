#!/usr/bin/env bash
# Installs the NOC daemons as systemd services, from a prebuilt release bundle or from a
# source checkout.
#
# The vessel and shore daemons run on separate machines:
# - vessel: runs on ships to capture and forward network traffic
# - shore: runs at the data center to receive and process traffic
#
# Each role installs only what it needs:
# - vessel gets dumpcap capabilities, TPM group access, 16 MB pipe limit, and WARP key staging
# - shore gets the receiving daemon and Malcolm ingest directory permissions
#
# Where the binaries come from:
# - a release bundle (this script sits in <bundle>/deploy/, next to <bundle>/bin/): the
#   prebuilt binaries in bin/ are installed as they are; no Rust toolchain is needed;
# - a source checkout (dev/ or prod/): they are built first with cargo.
#
# Works on a fresh machine and on one that is already set up, and starts nothing new:
# - fresh: installs the binaries and units and puts config templates in /etc/noc. What the
#   host itself decides is filled in (the TPM transport, the identity key); what only the
#   operator knows (interfaces, shore address, the vessels a shore accepts) is left blank,
#   and the daemons refuse to start until it is set. Fill it in, then start the service;
# - already configured (an update): reinstalls the binaries and units, leaves every file in
#   /etc/noc exactly as it is, and restarts the services that were running.
#
# Usage:
#   sudo deploy/install.sh vessel           # aboard a vessel
#   sudo deploy/install.sh shore            # at the shore facility
#   sudo deploy/install.sh both             # one host running both (for testing only)
#
# The last section checks that what was installed can actually start. Every step here
# can succeed on a host where the daemon still refuses to run.

set -euo pipefail

usage() {
  # The markers name lines tools/make-prod-tree.sh removes; not shown here.
  sed -E 's/[[:space:]]+# \[(dev)-only\]$//' >&2 <<'USAGE'
usage: install.sh vessel|shore|both [options]

  vessel  the capture side: dumpcap, FIFO sysctl, TPM access, WARP key staging
  shore   the receiving side: listener, identity lookup, Malcolm ingest
  both    a single test host running the pair (not a production layout)

Options:
  --no-build     source checkout: install what is already in target/release, without building

The vessel needs a TPM 2.0 (/dev/tpmrm0) and a WARP device key (warp-cli registered, on
the MASQUE tunnel protocol); without either it stops before changing anything.

Nothing is started on a fresh host: fill in /etc/noc, then systemctl enable --now.

The role is deliberately required: the two daemons are meant to be installed on
different machines.
USAGE
  exit 2
}

ROLE="${1:-}"
case "$ROLE" in
  vessel) WANT_VESSEL=1; WANT_SHORE=0 ;;
  shore)  WANT_VESSEL=0; WANT_SHORE=1 ;;
  both)   WANT_VESSEL=1; WANT_SHORE=1 ;;
  *) usage ;;
esac
shift

DO_BUILD=1; NO_WARP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --no-build) DO_BUILD=0 ;;
    -h|--help) usage ;;
    *) echo "unknown option: $1" >&2; usage ;;
  esac
  shift
done

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SUDO="sudo"
[ "$(id -u)" = 0 ] && SUDO=""

# A release bundle carries its binaries in bin/ and describes itself in BUNDLE.
if [ -f "$ROOT/BUNDLE" ] && [ -d "$ROOT/bin" ]; then
  BUNDLE=1; BIN_DIR="$ROOT/bin"
  echo "==> role: $ROLE (release bundle: $(tr '\n' ' ' < "$ROOT/BUNDLE"))"
  B_ARCH="$(sed -n 's/^arch=//p' "$ROOT/BUNDLE")"
  if [ -n "$B_ARCH" ] && [ "$B_ARCH" != "$(uname -m)" ]; then
    echo "this bundle is built for $B_ARCH, but this host is $(uname -m): download the $(uname -m) bundle" >&2
    exit 1
  fi
else
  BUNDLE=0; BIN_DIR="$ROOT/target/release"
  echo "==> role: $ROLE (source checkout: $ROOT)"
fi

# ---------------------------------------------------------------------------
# Decide everything that can stop the install before changing anything: a vessel with no
# TPM, or with no identity key to sign with, would otherwise end up half installed.
# ---------------------------------------------------------------------------
TPM_DEV=""; USE_SWTPM=0; KEY_SRC=""; PUBKEY=""
# The identity is decided for a new config, and for one whose key_file is still blank.
NEED_KEY=0
if [ "$WANT_VESSEL" = 1 ]; then
  if [ ! -f /etc/noc/vessel.toml ] \
     || grep -qE '^[[:space:]]*key_file[[:space:]]*=[[:space:]]*""' /etc/noc/vessel.toml; then
    NEED_KEY=1
  fi
  echo "==> TPM for the at-rest KEKs"
  for d in /dev/tpmrm0 /dev/tpm0; do
    [ -c "$d" ] && { TPM_DEV="$d"; break; }
  done
  if [ -n "$TPM_DEV" ]; then
    echo "    TPM device: $TPM_DEV ($(stat -c '%U:%G %a' "$TPM_DEV"))"
  fi
  if [ -z "$TPM_DEV" ] && [ "$USE_SWTPM" = 0 ]; then
    echo "    no TPM device (/dev/tpmrm0, /dev/tpm0). The vessel keeps its at-rest keys in a" >&2
    echo "    TPM 2.0 and will not run without one: enable the chip (or the VM's vTPM) and re-run." >&2
    exit 1
  fi

  # The identity key, unless the config already names one.
  if [ "$NEED_KEY" = 1 ]; then
    echo "==> identity key"
    REG=/var/lib/cloudflare-warp/reg.json
    WARP_STATE=absent
    if $SUDO test -f "$REG"; then
      # Only the MASQUE tunnel protocol gives the device a P-256 key; WireGuard gives X25519.
      WARP_STATE="$($SUDO python3 - "$REG" <<'PY'
import base64, json, sys
reg = json.load(open(sys.argv[1]))
der = base64.b64decode(reg.get("secret_key", ""))
ok = len(der) >= 64 and der[0] == 0x30 and bytes.fromhex("2a8648ce3d030107") in der
print("p256 " + reg.get("public_key", "") if ok else "not-p256")
PY
)" || WARP_STATE=unreadable
    fi
    if [ "$KEY_SRC" != own ]; then
      case "$WARP_STATE" in
        p256\ *)
          KEY_SRC=warp; PUBKEY="${WARP_STATE#p256 }"
          echo "    WARP device key found (P-256): staged from $REG at every start" ;;
        not-p256)
          echo "    the WARP registration in $REG holds no P-256 key: this device is on the" >&2
          echo "    WireGuard tunnel protocol. Switch it to MASQUE (Zero Trust device settings)," >&2
          echo "    re-register, and re-run. (warp-cli settings | grep -i 'tunnel protocol')" >&2
          exit 1 ;;
        *)
          echo "    no WARP device key detected ($REG $([ "$WARP_STATE" = absent ] && echo 'does not exist' || echo 'is unreadable'))." >&2
          echo "    The vessel signs with its WARP device key: install the WARP client, register it" >&2
          echo "    (warp-cli registration new), set the tunnel protocol to MASQUE, and re-run." >&2
          exit 1 ;;
      esac
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Build, from a source checkout only. As the user who ran sudo, so it uses their Rust
# toolchain and the build tree stays theirs; cargo only rebuilds what changed.
# ---------------------------------------------------------------------------
if [ "$BUNDLE" = 0 ] && [ "$DO_BUILD" = 1 ]; then
  PKGS=()
  if [ "$WANT_VESSEL" = 1 ]; then PKGS+=(-p noc-vessel); fi
  if [ "$WANT_SHORE" = 1 ]; then PKGS+=(-p noc-shore); fi
  echo "==> build (release)"
  BUILD_CMD="cd $(printf %q "$ROOT") && cargo build --release ${PKGS[*]}"
  if [ "$(id -u)" = 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
    # A login shell, so ~/.cargo/env (rustup) is on PATH.
    sudo -u "$SUDO_USER" -H bash -lc "$BUILD_CMD" \
      || { echo "build failed (is Rust installed for $SUDO_USER? https://rustup.rs)" >&2; exit 1; }
  else
    command -v cargo >/dev/null || { [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"; }
    command -v cargo >/dev/null || { echo "cargo not found: install Rust (https://rustup.rs) or use --no-build" >&2; exit 1; }
    bash -c "$BUILD_CMD" || { echo "build failed" >&2; exit 1; }
  fi
fi

# Check that the binaries needed for the chosen role exist before proceeding.
NEEDED=()
if [ "$WANT_VESSEL" = 1 ]; then NEEDED+=(noc-vessel); fi
if [ "$WANT_SHORE" = 1 ]; then NEEDED+=(noc-shore); fi
for b in "${NEEDED[@]}"; do
  [ -x "$BIN_DIR/$b" ] || { echo "missing $BIN_DIR/$b$([ "$BUNDLE" = 0 ] && echo ' -- build it (drop --no-build)')" >&2; exit 1; }
done

# ---------------------------------------------------------------------------
# Packages needed at run time: python3 for noc-console on either role; on a vessel also
# dumpcap, setcap, the TPM (TSS 2.0) libraries and the software TPM where there is no
# chip. The shore binary itself needs nothing beyond the C library.
# ---------------------------------------------------------------------------
PKG=(python3)   # noc-console, on either role
if [ "$WANT_VESSEL" = 1 ]; then
  PKG+=(wireshark-common libcap2-bin libtss2-esys-3.0.2-0t64 libtss2-tctildr0t64 libtss2-tcti-device0t64)
fi
MISSING=()
for p in "${PKG[@]}"; do
  dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'install ok installed' || MISSING+=("$p")
done
if [ ${#MISSING[@]} -gt 0 ]; then
  echo "==> packages: ${MISSING[*]}"
  $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -q "${MISSING[@]}" >/dev/null \
    || { echo "    could not install ${MISSING[*]} (apt-get update first?)" >&2; exit 1; }
fi
if [ "$WANT_VESSEL" = 1 ]; then
  if ldd "$BIN_DIR/noc-vessel" | grep -q 'not found'; then
    echo "noc-vessel cannot load: $(ldd "$BIN_DIR/noc-vessel" | grep 'not found' | awk '{print $1}' | tr '\n' ' ')" >&2
    exit 1
  fi
fi

# Which services were running before, so an update can restart exactly those.
WAS_ACTIVE=()
for u in noc-vessel noc-shore; do systemctl is-active --quiet "$u" 2>/dev/null && WAS_ACTIVE+=("$u"); done

echo "==> service account(s)"
ACCOUNTS=()
if [ "$WANT_VESSEL" = 1 ]; then ACCOUNTS+=(noc-vessel); fi
if [ "$WANT_SHORE" = 1 ]; then ACCOUNTS+=(noc-shore); fi
for u in "${ACCOUNTS[@]}"; do
  if ! id -u "$u" >/dev/null 2>&1; then
    $SUDO useradd --system --no-create-home --shell /usr/sbin/nologin "$u"
    echo "    created system user $u"
  else
    echo "    $u already exists"
  fi
done

if [ "$WANT_VESSEL" = 1 ]; then
  if ! getent group tss >/dev/null; then
    $SUDO groupadd --system tss
    echo "    created group tss (the vessel unit joins it to reach the TPM)"
  fi
fi

echo "==> binaries -> /usr/local/bin"
if [ "$WANT_VESSEL" = 1 ]; then
  $SUDO install -m 0755 "$BIN_DIR/noc-vessel" /usr/local/bin/noc-vessel
  $SUDO install -m 0755 "$ROOT/deploy/noc-stage-warp-key.sh" /usr/local/bin/noc-stage-warp-key
fi
if [ "$WANT_SHORE" = 1 ]; then
  $SUDO install -m 0755 "$BIN_DIR/noc-shore"  /usr/local/bin/noc-shore
fi
# The live console (reads the daemons' status snapshots and journal), on either role.
$SUDO install -m 0755 "$ROOT/deploy/noc-console" /usr/local/bin/noc-console

if [ "$WANT_VESSEL" = 1 ]; then
  echo "==> dumpcap raw-capture capability (the daemon itself stays unprivileged)"
  DUMPCAP="$(command -v dumpcap || true)"
  if [ -n "$DUMPCAP" ]; then
    $SUDO setcap cap_net_raw,cap_net_admin=eip "$DUMPCAP"
    echo "    setcap on $DUMPCAP -> $($SUDO getcap "$DUMPCAP")"
  else
    echo "    WARNING: dumpcap not found in PATH; install wireshark-common and re-run" >&2
  fi

  echo "==> sysctl fs.pipe-max-size (>= 16 MB) and BBR congestion control"
  # BBR is a kernel module: load it now and at every boot, before the sysctl names it.
  echo tcp_bbr | $SUDO tee /etc/modules-load.d/noc-bbr.conf >/dev/null
  $SUDO modprobe tcp_bbr 2>/dev/null || echo "    WARNING: could not load tcp_bbr; the kernel may not provide BBR" >&2
  $SUDO install -m 0644 "$ROOT/deploy/60-noc.conf" /etc/sysctl.d/60-noc.conf
  # A kernel without BBR rejects that one line; the rest still applies, and the check below says so.
  $SUDO sysctl --system >/dev/null 2>&1 || echo "    WARNING: some sysctl settings were rejected (see the checks below)" >&2
  echo "    fs.pipe-max-size = $($SUDO sysctl -n fs.pipe-max-size)"
  echo "    net.ipv4.tcp_congestion_control = $($SUDO sysctl -n net.ipv4.tcp_congestion_control)"
fi

echo "==> /etc/noc"
$SUDO install -d -m 0755 /etc/noc

echo "==> systemd unit(s)"
if [ "$WANT_VESSEL" = 1 ]; then
  $SUDO install -m 0644 "$ROOT/deploy/noc-vessel.service" /etc/systemd/system/noc-vessel.service
fi
if [ "$WANT_SHORE" = 1 ]; then
  $SUDO install -m 0644 "$ROOT/deploy/noc-shore.service"  /etc/systemd/system/noc-shore.service
fi
$SUDO systemctl daemon-reload

# ---------------------------------------------------------------------------
# Configuration templates. Installed only where there is no file yet; an existing config
# is the operator's and is never touched. In a fresh vessel config the installer fills in
# what it found on the host (the TPM transport, the identity key) and leaves blank what only
# the operator knows (what to capture, where the shore is); the daemons refuse to start
# until that is filled in.
# ---------------------------------------------------------------------------
TEMPLATES=()
# template <source> <dest> <mode>: 0 if it installed the file.
template() {
  if [ -f "$2" ]; then echo "    $2 exists: kept as it is"; return 1; fi
  $SUDO install -m "$3" "$1" "$2"; TEMPLATES+=("$2"); echo "    installed template $2"
}
# set_key <file> <key> <toml value>: replace the first `key = ...` line, keeping its comment.
set_key() {
  $SUDO python3 - "$1" "$2" "$3" <<'PY'
import re, sys
p, k, v = sys.argv[1:4]
s = open(p).read()
pat = re.compile(r'^(\s*)' + re.escape(k) + r'(\s*=\s*)("[^"]*"|\[[^\]]*\]|[^\s#]+)', re.M)
m = pat.search(s)
assert m, f"{k} not found in {p}"
s = s[:m.start()] + m.group(1) + k + m.group(2) + v + s[m.end():]
open(p, "w").write(s)
PY
}
if [ "$WANT_VESSEL" = 1 ]; then
  echo "==> vessel config"
  if template "$ROOT/vessel/vessel.example.toml" /etc/noc/vessel.toml 0644; then
    TCTI="device:/dev/tpmrm0"
    set_key /etc/noc/vessel.toml tcti "\"$TCTI\""
    echo "    [tpm] tcti = \"$TCTI\""
  fi
  if [ "$NEED_KEY" = 1 ]; then
    if [ "$KEY_SRC" = warp ]; then
      set_key /etc/noc/vessel.toml key_file '"/run/noc-vessel/warp_identity.key"'
      echo "    [identity] key_file = the WARP device key (staged at every start)"
    fi
  fi
  # A key in /etc/noc must be the service user's and nobody else's.
  if [ -f /etc/noc/vessel.key ]; then
    $SUDO chown noc-vessel:noc-vessel /etc/noc/vessel.key; $SUDO chmod 0400 /etc/noc/vessel.key
  fi
fi
if [ "$WANT_SHORE" = 1 ]; then
  echo "==> shore config"
  template "$ROOT/shore/shore.example.toml" /etc/noc/shore.toml 0644 || true
  # The Devices API token must be readable by the service user and nobody else.
  if [ -f /etc/noc/cf_api.token ]; then
    $SUDO chown noc-shore:noc-shore /etc/noc/cf_api.token; $SUDO chmod 0400 /etc/noc/cf_api.token
  fi
fi

echo
echo "installed ($ROLE). Watch it with: sudo noc-console"
if [ -n "$PUBKEY" ]; then
  cat <<EOF

  VESSEL identity: the shore must know this vessel's key. On a shore using a device table
  rather than the Cloudflare lookup, add this line to the shore's
  /etc/noc/devices.toml (any vessel id you like), then restart noc-shore:
      "$PUBKEY" = "<vessel id>"
EOF
  [ "$KEY_SRC" != warp ] || echo "  (not needed when the shore looks WARP devices up in Cloudflare, its default)"
fi
if [ "$ROLE" = both ]; then
  cat <<'EOF'

  NOTE: 'both' put the vessel and shore daemons on this one host. That is a test
  layout; in production each role gets its own machine.
EOF
fi

# ---------------------------------------------------------------------------
# Checks. Installing the files is not the same as being able to start: a missing
# TPM, a tcti pointing at a device that is not there, or a shore identity table
# that was never written all leave a clean install that fails at startup.
# ---------------------------------------------------------------------------
echo
echo "==> checks"
FAIL=0
ok()   { echo "    ok   $*"; }
bad()  { echo "    FAIL $*" >&2; FAIL=$((FAIL + 1)); }
note() { echo "    note $*"; }
TODO=0
todo() { echo "    TODO $*"; TODO=$((TODO + 1)); }

if [ "$WANT_VESSEL" = 1 ]; then
  [ -x /usr/local/bin/noc-vessel ] && ok "noc-vessel installed" || bad "noc-vessel missing"
  [ -f /etc/systemd/system/noc-vessel.service ] && ok "noc-vessel.service installed" \
    || bad "noc-vessel.service missing"

  DUMPCAP="$(command -v dumpcap || true)"
  if [ -z "$DUMPCAP" ]; then
    bad "dumpcap not in PATH (capture cannot run)"
  elif getcap "$DUMPCAP" 2>/dev/null | grep -q cap_net_raw; then
    ok "dumpcap has cap_net_raw"
  else
    bad "dumpcap lacks cap_net_raw: capture will fail with a permission error"
  fi

  PIPE_MAX="$(sysctl -n fs.pipe-max-size 2>/dev/null || echo 0)"
  if [ "$PIPE_MAX" -ge 16777216 ]; then
    ok "fs.pipe-max-size = $PIPE_MAX"
  else
    bad "fs.pipe-max-size = $PIPE_MAX, below the 16 MB FIFO"
  fi

  # Not a start-up blocker, but without BBR a lossy link delays data by tens of seconds.
  TCP_CC="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo unknown)"
  if [ "$TCP_CC" = bbr ]; then
    ok "TCP congestion control = bbr"
  else
    note "WARNING: TCP congestion control = $TCP_CC, not bbr; on a lossy link data will arrive tens of seconds late"
  fi

  if [ -n "$TPM_DEV" ]; then ok "TPM device $TPM_DEV present"; fi

  # What the operator still has to fill in. Not failures: a fresh install is expected to
  # stop here, and the daemon itself refuses to start until these are set.
  if [ -f /etc/noc/vessel.toml ]; then
    V=/etc/noc/vessel.toml
    grep -qE '^[[:space:]]*interfaces[[:space:]]*=[[:space:]]*\[[[:space:]]*\]' "$V" \
      && todo "vessel.toml [capture] interfaces: the interfaces to capture (ip -br link)"
    grep -qE '^[[:space:]]*shore_addr[[:space:]]*=[[:space:]]*""' "$V" \
      && todo "vessel.toml [transport] shore_addr: the shore's \"host:port\""
    TCTI="$(sed -nE 's/^[[:space:]]*tcti[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' "$V" | tail -1)"
    case "$TCTI" in
      device:*)
        DEV="${TCTI#device:}"
        [ -c "$DEV" ] && ok "tcti $TCTI resolves" \
          || todo "vessel.toml [tpm] tcti points at $DEV, which this host does not have"
        ;;
      swtpm:*)
        bad "tcti is $TCTI: this build runs only on a TPM device (device:/dev/tpmrm0)" ;;
      "") note "no [tpm] tcti in vessel.toml; the built-in default device:/dev/tpmrm0 applies" ;;
      *)  note "tcti $TCTI not checked" ;;
    esac
    KEYF="$(sed -nE 's/^[[:space:]]*key_file[[:space:]]*=[[:space:]]*"([^"]*)".*/\1/p' "$V" | tail -1)"
    case "$KEYF" in
      "") todo "vessel.toml [identity] key_file: re-run install.sh to detect the WARP device key" ;;
      /run/noc-vessel/warp_identity.key)
        [ -f /var/lib/cloudflare-warp/reg.json ] && ok "key_file is the WARP device key, staged at start" \
          || todo "key_file is the WARP device key, but this host has no WARP: point it at a key file" ;;
      *) [ -s "$KEYF" ] && ok "identity key $KEYF present" || todo "identity key $KEYF does not exist yet" ;;
    esac
  fi
fi

if [ "$WANT_SHORE" = 1 ]; then
  [ -x /usr/local/bin/noc-shore ] && ok "noc-shore installed" || bad "noc-shore missing"
  [ -f /etc/systemd/system/noc-shore.service ] && ok "noc-shore.service installed" \
    || bad "noc-shore.service missing"
  if [ -f /etc/noc/shore.toml ]; then
    T=/etc/noc/shore.toml
    if grep -qE '^[[:space:]]*cloudflare_account_id[[:space:]]*=' "$T"; then
      if grep -qE '^[[:space:]]*cloudflare_account_id[[:space:]]*=[[:space:]]*""' "$T"; then
        todo "shore.toml [shore.identity] cloudflare_account_id: the Zero Trust account id"
      else
        ok "vessels are looked up in the Cloudflare Devices API"
      fi
      TOKF="$(sed -nE 's/^[[:space:]]*api_token_file[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' "$T" | tail -1)"
      if [ -n "${NOC_CF_API_TOKEN:-}" ] || { [ -n "$TOKF" ] && $SUDO test -s "$TOKF"; }; then
        ok "Devices API token present"
      else
        todo "the read-only Devices API token in ${TOKF:-the api_token_file}: sudo install -m 0400 -o noc-shore -g noc-shore <token file> ${TOKF:-/etc/noc/cf_api.token}"
      fi
    else
      DEVF="$(sed -nE 's/^[[:space:]]*devices_file[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' "$T" | tail -1)"
      N="$(grep -cE '^[[:space:]]*"' "${DEVF:-/nonexistent}" 2>/dev/null || true)"
      if [ -z "$DEVF" ]; then
        todo "shore.toml [shore.identity]: set cloudflare_account_id, or devices_file"
      elif [ "${N:-0}" -gt 0 ]; then
        ok "device table $DEVF lists $N vessel(s)"
      else
        todo "$DEVF: a line per vessel, \"<public key>\" = \"<vessel id>\""
      fi
    fi
  fi
fi

echo
if [ "$FAIL" -ne 0 ]; then
  echo "$FAIL check(s) failed -- the daemon(s) will not start until these are fixed." >&2
  exit 1
fi
echo "host checks passed."

# ---------------------------------------------------------------------------
# Restart. Only an update does this: a service that was running is restarted on the new
# binaries. Nothing is started that was not already running.
# ---------------------------------------------------------------------------
RESTART=()
if [ "$WANT_SHORE" = 1 ]; then RESTART+=(noc-shore); fi     # shore first: the vessel connects to it
if [ "$WANT_VESSEL" = 1 ]; then RESTART+=(noc-vessel); fi
for u in "${RESTART[@]}"; do
  [[ " ${WAS_ACTIVE[*]-} " =~ " $u " ]] || continue
  echo "==> restarting $u (it was running)"
  $SUDO systemctl restart "$u"; sleep 2
  systemctl is-active --quiet "$u" && echo "    $u: active" \
    || { echo "    $u did not stay up -- see: journalctl -u $u -n 30" >&2; exit 1; }
done

if [ "$TODO" -gt 0 ] || [ ${#TEMPLATES[@]} -gt 0 ]; then
  echo
  if [ "$TODO" -gt 0 ]; then echo "$TODO value(s) to fill in (TODO above): the service refuses to start until they are set."; fi
  STARTS=()
  if [ "$WANT_SHORE" = 1 ] && ! systemctl is-active --quiet noc-shore; then STARTS+=(noc-shore); fi
  if [ "$WANT_VESSEL" = 1 ] && ! systemctl is-active --quiet noc-vessel; then
    STARTS+=(noc-vessel)
  fi
  if [ ${#STARTS[@]} -gt 0 ]; then echo "Then start it:  sudo systemctl enable --now ${STARTS[*]}"; fi
fi
exit 0
