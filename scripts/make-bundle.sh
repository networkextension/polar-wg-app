#!/bin/bash
# Stage a self-contained tarball that a target machine can extract and
# install without needing the source tree.
#
#   sh scripts/make-bundle.sh              -> dist/wg-mac-YYYYMMDD-<sha>.tar.gz
#   sh scripts/make-bundle.sh v1.2.3       -> dist/wg-mac-v1.2.3.tar.gz
#
# On the target:
#   tar xzf wg-mac-<ver>.tar.gz
#   cd wg-mac-<ver>
#   sudo ./scripts/install.sh wg0

set -euo pipefail

SRCDIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SRCDIR"

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
    SHA=$(git rev-parse --short=8 HEAD 2>/dev/null || echo "nogit")
    VERSION="$(date +%Y%m%d)-$SHA"
fi

NAME="wg-mac-$VERSION"
DIST="$SRCDIR/dist"
STAGE="$DIST/$NAME"

echo "==> Building (make all)"
make all >/dev/null

echo "==> Staging $STAGE"
rm -rf "$STAGE"
mkdir -p "$STAGE/build" "$STAGE/scripts"
cp build/wgctl   "$STAGE/build/"
cp build/wg_core "$STAGE/build/"
cp scripts/install.sh                          "$STAGE/scripts/"
cp scripts/uninstall.sh                        "$STAGE/scripts/"
cp scripts/join.sh                             "$STAGE/scripts/"
cp scripts/wgctl-agent.sh                      "$STAGE/scripts/"
cp scripts/wg-postup.sh                        "$STAGE/scripts/"
cp scripts/com.wireguard.wg-mac.plist.template "$STAGE/scripts/"
cp scripts/com.wireguard.wgctl-agent.plist     "$STAGE/scripts/"

# Version stamp readable by install.sh / agent for /v1/register agent_ver.
echo "$VERSION" > "$STAGE/VERSION"

# Top-level README so the target user sees instructions without browsing.
cat > "$STAGE/README.txt" <<EOF
wg-mac $VERSION — portable WireGuard CLI bundle for macOS

Install (target machine):
  tar xzf $NAME.tar.gz       # if you haven't already
  cd $NAME
  sudo ./scripts/install.sh wg0

That copies wgctl + wg_core to /usr/local/bin, drops a launchd plist,
and (if /etc/wireguard/wg0.conf exists) bootstraps it.

To remove:
  sudo ./scripts/uninstall.sh wg0

Keys + sample config (run on either machine):
  wgctl genkey | tee priv.key | wgctl pubkey > pub.key
  wgctl genpsk

Build info:
  built on:    $(date)
  source rev:  $(git rev-parse HEAD 2>/dev/null || echo "no-git")
  binaries:    arm64 (run \`file build/wg_core\` to confirm)
EOF

echo "==> Tarball"
TAR="$DIST/$NAME.tar.gz"
(cd "$DIST" && tar czf "$NAME.tar.gz" "$NAME")
echo ""
echo "  $TAR"
echo "  size: $(du -h "$TAR" | awk '{print $1}')"
echo ""
echo "  scp $TAR user@host:/tmp/"
echo "  ssh user@host 'cd /tmp && tar xzf $NAME.tar.gz && cd $NAME && sudo ./scripts/install.sh wg0'"
