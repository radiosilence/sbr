#!/usr/bin/env bash
# End-to-end check of sbr inside a real macOS packet tunnel (NetworkExtension).
# See README.md in this directory. Exit status is the number of failed checks.
#
#   apple/TunnelCheck/tunnel-check.sh
#
# Environment:
#   SBR_TUNNEL_CHECK_SKIP_BUILD=1   reuse the last build
#   SBR_TUNNEL_CHECK_HTTPS_URL      HTTPS URL fetched through the tunnel
#   SBR_TUNNEL_CHECK_STUN           STUN server host:port
#   SBR_TUNNEL_CHECK_MIN_MBPS       minimum bulk rate in MB/s (default 20)
#   SBR_TUNNEL_CHECK_BULK_MB        bulk download size in MiB (default 32)
#   APPLE_API_KEY_PATH / _ID / APPLE_API_ISSUER_ID   signing via App Store Connect
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
https_url=${SBR_TUNNEL_CHECK_HTTPS_URL:-https://www.apple.com/library/test/success.html}
stun=${SBR_TUNNEL_CHECK_STUN:-stun.cloudflare.com:3478}
min_mbps=${SBR_TUNNEL_CHECK_MIN_MBPS:-20}
bulk_mb=${SBR_TUNNEL_CHECK_BULK_MB:-32}

# The tun owns 198.19.250.0/24 and nothing else (auto_route off: only the
# interface subnet is routed into it, and no DNS settings are pushed). Test
# destinations are addresses in that subnet that the config rewrites.
net=198.19.250
tun_dns=$net.2
via_hop=$net.10   # TCP and UDP through a socks outbound to a local sbr
udp_hop=$net.11
direct_lo=$net.12 # direct outbound to loopback: the tunnel's stack alone
https_ip=$net.20
stun_ip=$net.21

T=$(command -v gtimeout || command -v timeout || true)
[ -n "$T" ] || { echo "needs timeout(1): brew install coreutils" >&2; exit 2; }

app=$here/build/dd/Build/Products/Debug/SbrTunnelCheck.app
ctl=$app/Contents/MacOS/SbrTunnelCheck
rust_target=$([ "$(uname -m)" = arm64 ] && echo aarch64-apple-darwin || echo x86_64-apple-darwin)

if [ "${SBR_TUNNEL_CHECK_SKIP_BUILD:-0}" != 1 ]; then
  echo "== build"
  (cd "$repo" && MACOSX_DEPLOYMENT_TARGET=12.0 CARGO_PROFILE_RELEASE_DEBUG=0 \
    cargo build -q --release -p sbr-apple --target "$rust_target")
  (cd "$repo" && cargo build -q --release -p sbr)
  key=${APPLE_API_KEY_PATH:-$HOME/.appstoreconnect/private_keys/AuthKey_${APPLE_API_KEY_ID:-9G3FHWD2RH}.p8}
  auth=()
  if [ -f "$key" ]; then
    auth=(-authenticationKeyPath "$key"
      -authenticationKeyID "${APPLE_API_KEY_ID:-9G3FHWD2RH}"
      -authenticationKeyIssuerID "${APPLE_API_ISSUER_ID:-54135b80-f695-46ac-9a60-9fbd67c80da6}")
  fi
  (cd "$here" && mise exec -- xcodegen generate --quiet)
  mkdir -p "$here/build"
  if ! xcodebuild build -project "$here/SbrTunnelCheck.xcodeproj" -scheme SbrTunnelCheck \
    -configuration Debug -destination 'platform=macOS' -derivedDataPath "$here/build/dd" \
    -allowProvisioningUpdates -allowProvisioningDeviceRegistration "${auth[@]}" \
    > "$here/build/xcodebuild.log" 2>&1; then
    grep -E 'error:' "$here/build/xcodebuild.log" || tail -n 40 "$here/build/xcodebuild.log"
    exit 2
  fi
  # NetworkExtension finds the provider through LaunchServices / PlugInKit.
  /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "$app"
  pluginkit -a "$app/Contents/PlugIns/SbrTunnelCheckExtension.appex"
fi
[ -x "$ctl" ] || { echo "no build at $app" >&2; exit 2; }

work=$(mktemp -d "${TMPDIR:-/tmp}/sbr-tunnel-check.XXXXXX")
pids=()
cleanup() {
  "$T" -s KILL 20 "$ctl" down 15 || echo "WARNING: could not confirm the tunnel is down; run: $ctl down" >&2
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
  rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

free_port() { python3 -I -c 'import socket,sys; s=socket.socket(socket.AF_INET, int(sys.argv[1])); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])' "$1"; }
resolve() { dig +short +time=3 +tries=2 A "$1" | grep -E '^[0-9.]+$' | head -1; }

https_host=$(echo "$https_url" | sed -E 's#^https://([^/:]+).*#\1#')
stun_host=${stun%:*}
stun_port=${stun##*:}
real_https=$(resolve "$https_host")
real_stun=$(resolve "$stun_host")
[ -n "$real_https" ] && [ -n "$real_stun" ] || { echo "cannot resolve $https_host / $stun_host" >&2; exit 2; }
http_port=$(free_port 1)
udp_port=$(free_port 2)
socks_port=$(free_port 1)

echo "== local servers"
mkdir -p "$work/www"
head -c $((bulk_mb * 1048576)) /dev/urandom > "$work/www/blob"
want=$(shasum -a 256 "$work/www/blob" | cut -d' ' -f1)
python3 -I -m http.server "$http_port" --bind 127.0.0.1 --directory "$work/www" > "$work/http.log" 2>&1 &
pids+=($!)
python3 -I -c '
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", int(sys.argv[1])))
while True:
    d, a = s.recvfrom(65535)
    s.sendto(d, a)
' "$udp_port" &
pids+=($!)
cat > "$work/server.json" <<JSON
{
  "log": {"level": "warn"},
  "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": $socks_port}],
  "outbounds": [{"type": "direct", "tag": "direct"}],
  "route": {"rules": [{"ip_cidr": ["$net.0/24"], "action": "route-options", "override_address": "127.0.0.1"}]}
}
JSON
"$repo/target/release/sbr" run -c "$work/server.json" > "$work/server.log" 2>&1 &
pids+=($!)

cat > "$work/tunnel.json" <<JSON
{
  "log": {"level": "debug"},
  "dns": {"servers": [{"type": "udp", "tag": "upstream", "server": "1.1.1.1"}]},
  "inbounds": [{"type": "tun", "tag": "tun-in", "address": ["$net.1/24"], "mtu": 1280,
                "stack": "mixed", "auto_route": false}],
  "outbounds": [
    {"type": "direct", "tag": "direct"},
    {"type": "socks", "tag": "hop", "server": "127.0.0.1", "server_port": $socks_port}
  ],
  "route": {
    "rules": [
      {"action": "sniff"},
      {"protocol": "dns", "action": "hijack-dns"},
      {"ip_cidr": ["$via_hop/32", "$udp_hop/32"], "outbound": "hop"},
      {"ip_cidr": ["$direct_lo/32"], "action": "route-options", "override_address": "127.0.0.1"},
      {"ip_cidr": ["$https_ip/32"], "action": "route-options", "override_address": "$real_https"},
      {"ip_cidr": ["$stun_ip/32"], "action": "route-options", "override_address": "$real_stun"}
    ],
    "final": "direct"
  }
}
JSON
"$repo/target/release/sbr" check -c "$work/tunnel.json"

default_before=$(route -n get default 2>/dev/null | awk '/interface:/ {print $2}')

echo "== tunnel up"
up_limit=60
if [ "$("$T" 20 "$ctl" status 2>/dev/null)" = "not installed" ]; then
  echo "First run: macOS now asks to allow the VPN configuration \"sbr tunnel check\". Click Allow."
  up_limit=300
fi
if ! "$T" -s KILL "$up_limit" "$ctl" up 30 < "$work/tunnel.json"; then
  echo "FAIL tunnel did not come up within $up_limit s. If the VPN configuration prompt was not"
  echo "     answered, run again and click Allow. Extension log:"
  log show --last 2m --style compact --predicate 'subsystem BEGINSWITH "cc.blit.sbr.check"' | tail -n 40
  exit 1
fi

failures=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; failures=$((failures + 1)); }

utun=$(route -n get "$via_hop" 2>/dev/null | awk '/interface:/ {print $2}')
case "$utun" in
  utun*) pass "route: $net.0/24 is on $utun" ;;
  *) fail "route: $via_hop goes via ${utun:-nothing}, not a utun" ;;
esac
default_during=$(route -n get default 2>/dev/null | awk '/interface:/ {print $2}')
[ "$default_during" = "$default_before" ] && pass "default route untouched ($default_during)" \
  || fail "default route moved: $default_before -> $default_during"
scutil --dns | grep -q "$tun_dns" && fail "system DNS now points at the tunnel" || pass "system DNS untouched"

if out=$("$T" 20 curl -sS --max-time 15 --resolve "$https_host:443:$https_ip" -o /dev/null \
  -w '%{http_code} %{time_total}s' "$https_url" 2>&1) && [[ $out =~ ^[23] ]]; then
  pass "tcp: HTTPS $https_url via the tunnel (direct to $real_https): $out"
else
  fail "tcp: HTTPS $https_url: $out"
fi

if ans=$("$T" 10 dig +short +time=3 +tries=2 "@$tun_dns" "$https_host" A 2>&1) && [ -n "$ans" ]; then
  pass "dns: $https_host via the tunnel's DNS (hijack-dns -> 1.1.1.1): $(echo "$ans" | tr '\n' ' ')"
else
  fail "dns: no answer from $tun_dns for $https_host: $ans"
fi

if out=$("$T" 15 python3 -I -c '
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.connect((sys.argv[1], int(sys.argv[2])))
for n in (1, 1200, 4000):  # 4000 exceeds the 1280 MTU: fragmented both ways
    m = bytes(i % 251 for i in range(n))
    s.send(m)
    if s.recv(65535) != m:
        sys.exit("size %d: mismatch" % n)
print("1, 1200 and 4000 bytes echoed")
' "$udp_hop" "$udp_port" 2>&1); then
  pass "udp: echo through the socks hop: $out"
else
  fail "udp: echo through the socks hop: $out"
fi

if out=$("$T" 15 python3 -I -c '
import os, socket, struct, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
tid = os.urandom(12)
req = struct.pack("!HHI", 1, 0, 0x2112A442) + tid
for _ in range(3):
    s.sendto(req, (sys.argv[1], int(sys.argv[2])))
    try:
        d, _ = s.recvfrom(2048)
        break
    except socket.timeout:
        pass
else:
    sys.exit("no STUN response")
if d[8:20] != tid:
    sys.exit("STUN transaction id mismatch")
i = 20
while i + 4 <= len(d):
    t, l = struct.unpack("!HH", d[i:i + 4])
    if t == 0x20 and d[i + 5] == 1:
        port = struct.unpack("!H", d[i + 6:i + 8])[0] ^ 0x2112
        ip = bytes(a ^ b for a, b in zip(d[i + 8:i + 12], b"\x21\x12\xa4\x42"))
        print("mapped address %s:%d" % (socket.inet_ntoa(ip), port))
        break
    i += 4 + l + (-l % 4)
else:
    print("binding response without XOR-MAPPED-ADDRESS")
' "$stun_ip" "$stun_port" 2>&1); then
  pass "udp: STUN $stun via the tunnel: $out"
else
  fail "udp: STUN $stun: $out"
fi

bulk() { # label, address
  local out got
  if out=$("$T" 120 curl -sS --max-time 100 -o "$work/blob.out" -w '%{speed_download}' \
    "http://$2:$http_port/blob" 2>&1); then
    got=$(shasum -a 256 "$work/blob.out" | cut -d' ' -f1)
    local mbps
    mbps=$(awk -v b="$out" 'BEGIN { printf "%.0f", b / 1048576 }')
    if [ "$got" != "$want" ]; then
      fail "bulk ($1): $bulk_mb MiB arrived corrupted"
    elif [ "$mbps" -lt "$min_mbps" ]; then
      fail "bulk ($1): $bulk_mb MiB at $mbps MB/s, below $min_mbps MB/s"
    else
      pass "bulk ($1): $bulk_mb MiB, sha256 ok, $mbps MB/s"
    fi
  else
    fail "bulk ($1): $out"
  fi
  rm -f "$work/blob.out"
}
bulk "tun stack, direct to loopback" "$direct_lo"
bulk "through the socks hop" "$via_hop"

echo "== extension stats: $("$T" 10 "$ctl" stats 2>&1 || true)"
if [ "$failures" -gt 0 ]; then
  echo "== extension log (in-memory tail)"
  "$T" 10 "$ctl" logs 2>&1 | tail -n 60 || true
fi
echo "== $failures failed"
exit "$failures"
