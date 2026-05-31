#!/bin/bash
# make-bundle-ios.sh — package wg-mac-ios into a tarball ready to ship and
# unpack on a jailbroken iPhone / iPad.
#
# Usage:
#   bash scripts/make-bundle-ios.sh [VERSION]
#
# Output: dist/wg-mac-ios-arm64-<ver>.tar.gz
#
# Inside the tarball:
#   wg-mac-ios-arm64-<ver>/
#     VERSION
#     install.sh                # creates /usr/local/{bin,sbin,libexec/wg-mac} + /etc/{wireguard,wgctl}
#     bin/{wg_core,wgctl}       # cross-compiled iOS arm64 binaries
#     sbin/{join.sh,wgctl-agent}
#     libexec/postup.sh
#     launchd/com.wireguard.wg-mac.wg0.plist
#     README.md

set -euo pipefail
cd "$(dirname "$0")/.."   # repo root

VERSION="${1:-$(date +%Y%m%d)-$(git rev-parse --short=8 HEAD 2>/dev/null || echo dev)}"
STAGE_NAME="wg-mac-ios-arm64-${VERSION}"
STAGE=$(mktemp -d)/$STAGE_NAME
OUT_DIR=dist
OUT_TGZ="${OUT_DIR}/${STAGE_NAME}.tar.gz"

# 1. Build (or reuse) binaries.
if [ ! -x build/ios-arm64/wg_core ] || [ ! -x build/ios-arm64/wgctl ]; then
    echo "==> binaries missing — running scripts/build-ios-cli.sh"
    bash scripts/build-ios-cli.sh
fi

# 2. Stage.
echo "==> staging $STAGE"
mkdir -p "$STAGE/bin" "$STAGE/sbin" "$STAGE/libexec" "$STAGE/launchd"
echo "$VERSION" > "$STAGE/VERSION"
cp build/ios-arm64/wg_core   "$STAGE/bin/wg_core"
cp build/ios-arm64/wgctl     "$STAGE/bin/wgctl"
cp scripts/install-ios.sh    "$STAGE/install.sh"
cp scripts/join-ios.sh       "$STAGE/sbin/join.sh"
cp scripts/wgctl-agent.sh    "$STAGE/sbin/wgctl-agent"
cp scripts/wg-postup.sh      "$STAGE/libexec/postup.sh"
chmod 755 "$STAGE/install.sh" \
          "$STAGE/sbin/join.sh" \
          "$STAGE/sbin/wgctl-agent" \
          "$STAGE/libexec/postup.sh" \
          "$STAGE/bin/wg_core" \
          "$STAGE/bin/wgctl"

# 3. launchd plist for auto-start (one per iface; ship a wg0 template).
cat > "$STAGE/launchd/com.wireguard.wg-mac.wg0.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.wireguard.wg-mac.wg0</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/wg_core</string>
        <string>--tunnel</string>
        <string>--logical-name</string>
        <string>wg0</string>
        <string>/etc/wireguard/wg0.conf</string>
    </array>
    <key>KeepAlive</key><true/>
    <key>RunAtLoad</key><true/>
    <key>StandardOutPath</key><string>/var/log/wireguard.wg0.out.log</string>
    <key>StandardErrorPath</key><string>/var/log/wireguard.wg0.err.log</string>
</dict>
</plist>
PLIST

# 4. README inside the bundle (operator-facing quickstart).
cat > "$STAGE/README.md" <<EOF
# wg-mac for jailbroken iOS — ${VERSION}

User-space WireGuard for jailbroken iPhone / iPad. Opens utun directly
(no NetworkExtension), connects to a Polar control-plane mesh.

## Prerequisites

- Jailbroken iOS device (root, writable rootfs, code-signing relaxed).
- Tested on iOS 17 arm64; should work on any arm64 jailbreak that lets
  ad-hoc signed binaries run.
- Tools: \`bash\`, \`python3\`, \`curl\` (Procursus / Sileo defaults).
- Root SSH access from your build/host machine.

## Install

\`\`\`sh
# from your build host (or just AirDrop the file to the device)
scp ${STAGE_NAME}.tar.gz root@<ios-ip>:/tmp/
ssh root@<ios-ip>
cd /tmp && tar xzf ${STAGE_NAME}.tar.gz && cd ${STAGE_NAME}
bash install.sh
\`\`\`

Drops binaries into \`/usr/local/{bin,sbin,libexec/wg-mac}\` and creates
\`/etc/{wireguard,wgctl}\`. Idempotent.

## Join a Polar mesh

\`\`\`sh
/usr/local/sbin/wgctl-join \\
    --token=polar_wg_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \\
    --server=https://wg.4950.store:2443
\`\`\`

The script genkeys, POSTs \`/v1/register\`, writes
\`/etc/wireguard/wg0.conf\` + \`/etc/wgctl/config.json\`, brings up the
tunnel via \`wgctl up wg0\`, and prints a \`wgctl show\` snapshot.

## Auto-start at boot

\`\`\`sh
cp launchd/com.wireguard.wg-mac.wg0.plist /Library/LaunchDaemons/
launchctl bootstrap system /Library/LaunchDaemons/com.wireguard.wg-mac.wg0.plist
\`\`\`

## Hand-rolled tunnel (no Polar)

\`\`\`sh
/usr/local/bin/wgctl genkey > /etc/wireguard/wg0.key
PUB=\$(/usr/local/bin/wgctl pubkey < /etc/wireguard/wg0.key)
cat > /etc/wireguard/wg0.conf <<CONF
[Interface]
PrivateKey = \$(cat /etc/wireguard/wg0.key)
Address    = 10.0.0.2/24
ListenPort = 51820

[Peer]
PublicKey  = <hub-pubkey>
Endpoint   = hub.example.com:51820
AllowedIPs = 10.0.0.0/24
PersistentKeepalive = 25
CONF
/usr/local/bin/wgctl up wg0
\`\`\`

## Status / control

| Command                       | What it does                         |
|-------------------------------|--------------------------------------|
| \`wgctl show wg0\`            | handshake, peer stats, last-seen     |
| \`wgctl down wg0\`            | tear down tunnel                     |
| \`ifconfig utun0\`            | confirm interface state              |
| \`netstat -rn -f inet\`       | see installed routes                 |
| \`tail -f /var/log/wireguard.wg0.err.log\` | wg_core log if launchd is in use |

## See also

- \`doc/wg-mac-ios-jailbreak.md\` — design notes, code-signing notes,
  troubleshooting.
- \`doc/JOIN_PROTOCOL.md\` — /v1/register request/response shape.
EOF

# 5. Pack.
mkdir -p "$OUT_DIR"
echo "==> tar"
tar -C "$(dirname "$STAGE")" -czf "$OUT_TGZ" "$STAGE_NAME"

echo
ls -la "$OUT_TGZ"
echo
echo "Contents:"
tar -tzf "$OUT_TGZ" | sed 's/^/  /'
echo
echo "SHA256:"
shasum -a 256 "$OUT_TGZ"

# Cleanup stage dir.
rm -rf "$(dirname "$STAGE")"
