#!/usr/bin/env bash
#
# release-testflight.sh — TestFlight upload for WireGuardSampleApp-iOS.
#
#   xcodegen --spec project-ios.yml
#     → archive (Release, automatic signing, DEVELOPMENT_TEAM=Z9XG3YEP93)
#     → exportArchive (method=app-store-connect)
#     → upload to App Store Connect via -authenticationKey* flags
#
# Adapted from sibling /Users/apple/github/Latch/iOS/scripts/release.sh
# (same Apple ID / ASC team / key).
#
# Prerequisites (one-time, on the Apple Developer account):
#   1. Bundle IDs registered on developer.apple.com:
#        - com.change.wg           with Network Extensions capability
#        - com.change.wg.tunnel    with Network Extensions capability
#   2. App created in App Store Connect (My Apps → New App → iOS,
#      bundle id com.change.wg, primary language English).
#   3. AuthKey_<KEY_ID>.p8 at $HOME/.appstoreconnect/private_keys/
#      (already in place; override via ASC_KEY_PATH).
#   4. `make build-ios` from repo root has produced the xcframework
#      with iOS slices (this script will run it if missing).
#
# Usage:
#   ./scripts/release-testflight.sh                # full pipeline
#   ./scripts/release-testflight.sh --skip-upload  # archive + export only
#   ./scripts/release-testflight.sh --yes          # no confirmation prompt
#   ./scripts/release-testflight.sh --label rc1    # custom suffix
#

set -euo pipefail

# ── Pre-filled ASC credentials ─────────────────────────────────────────
: "${ASC_KEY_ID:=SAZ8WF9X6U}"
: "${ASC_ISSUER_ID:=69a6de92-f4fa-47e3-e053-5b8c7c11a4d1}"
# Prefer the canonical ASC location; fall back to ~/Downloads/.
if [[ -z "${ASC_KEY_PATH:-}" ]]; then
    if   [[ -f "$HOME/.appstoreconnect/private_keys/AuthKey_${ASC_KEY_ID}.p8" ]]; then
        ASC_KEY_PATH="$HOME/.appstoreconnect/private_keys/AuthKey_${ASC_KEY_ID}.p8"
    elif [[ -f "$HOME/Downloads/AuthKey_${ASC_KEY_ID}.p8" ]]; then
        ASC_KEY_PATH="$HOME/Downloads/AuthKey_${ASC_KEY_ID}.p8"
    else
        ASC_KEY_PATH="$HOME/.appstoreconnect/private_keys/AuthKey_${ASC_KEY_ID}.p8"
    fi
fi
TEAM_ID="Z9XG3YEP93"   # Apple Distribution: XiangBo Kong

# ── Project paths ──────────────────────────────────────────────────────
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$PROJECT_ROOT/.." && pwd)"
PROJECT_YML="$PROJECT_ROOT/project-ios.yml"
XCODEPROJ="$PROJECT_ROOT/WireGuardSampleApp-iOS.xcodeproj"
SCHEME="WireGuardSampleApp-iOS"

# ── CLI parsing ────────────────────────────────────────────────────────
SKIP_UPLOAD=0
AUTO_YES=0
LABEL=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-upload) SKIP_UPLOAD=1; shift ;;
        --yes|-y)      AUTO_YES=1; shift ;;
        --label)       LABEL="$2"; shift 2 ;;
        -h|--help)
            sed -n '3,30p' "${BASH_SOURCE[0]}"
            exit 0
            ;;
        *)
            echo "unknown arg: $1  (see --help)" >&2
            exit 2
            ;;
    esac
done

# ── Derive a stable archive label ──────────────────────────────────────
VERSION="$(awk '/MARKETING_VERSION:/ {gsub(/"/,"",$2); print $2; exit}' "$PROJECT_YML" || echo 0.1.0)"
BUILD="$(awk '/CURRENT_PROJECT_VERSION:/ {gsub(/"/,"",$2); print $2; exit}' "$PROJECT_YML" || echo 1)"
SHA="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo nogit)"
LABEL="${LABEL:+$LABEL-}$VERSION-b$BUILD-$SHA"

# BUILD_DIR on /tmp not the source tree — Xcode 26's distribution
# pipeline trips on TCC when writing into user-mounted /Volumes/...
# ("Copy failed" at IDEDistributionPackagingStep with no further
# detail). /tmp is system-owned, no permission gotchas.
BUILD_DIR="${BUILD_DIR:-/tmp/wg-mac-ios-build}"
ARCHIVE_PATH="$BUILD_DIR/WireGuard-$LABEL.xcarchive"
EXPORT_DIR="$BUILD_DIR/export-$LABEL"
EXPORT_PLIST="$BUILD_DIR/ExportOptions-$LABEL.plist"
IPA_PATH="$EXPORT_DIR/$SCHEME.ipa"

mkdir -p "$BUILD_DIR"

banner() { printf "\n\033[1;34m━━ %s\033[0m\n" "$1"; }
fail() { echo "✗ $1" >&2; exit 1; }

# ── 0. xcframework with iOS slices ────────────────────────────────────
if [[ ! -d "$REPO_ROOT/build/xcframework/WireGuardCore.xcframework/ios-arm64" ]]; then
    banner "make build-ios (xcframework missing)"
    (cd "$REPO_ROOT" && make build-ios)
fi

# ── 1. Regen project (idempotent) ──────────────────────────────────────
banner "xcodegen --spec project-ios.yml"
if command -v xcodegen >/dev/null; then
    (cd "$PROJECT_ROOT" && xcodegen --spec "$PROJECT_YML" | tail -3)
else
    echo "xcodegen not installed — assuming $XCODEPROJ is fresh"
fi

# ── 2. Archive ─────────────────────────────────────────────────────────
banner "xcodebuild archive → $ARCHIVE_PATH"
xcodebuild \
    -project "$XCODEPROJ" \
    -scheme "$SCHEME" \
    -configuration Release \
    -destination 'generic/platform=iOS' \
    -archivePath "$ARCHIVE_PATH" \
    -allowProvisioningUpdates \
    -authenticationKeyPath      "$ASC_KEY_PATH" \
    -authenticationKeyID        "$ASC_KEY_ID" \
    -authenticationKeyIssuerID  "$ASC_ISSUER_ID" \
    -skipPackagePluginValidation \
    CODE_SIGN_STYLE=Automatic \
    DEVELOPMENT_TEAM="$TEAM_ID" \
    archive | tail -8

# ── 3. ExportOptions.plist (manual signing) ────────────────────────────
# We pre-created the iOS App Store profiles via the ASC v1/profiles
# API ("5M8LCZCTTU iOS App Store" / "TFR5M8FZMC iOS App Store"), so
# Xcode can just reference them by name without trying to fetch a
# cloud-managed cert (which our API key role isn't allowed to do).
cat > "$EXPORT_PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>method</key>             <string>app-store-connect</string>
    <key>teamID</key>             <string>$TEAM_ID</string>
    <key>uploadSymbols</key>      <true/>
    <key>signingStyle</key>       <string>manual</string>
    <key>signingCertificate</key> <string>Apple Distribution</string>
    <key>provisioningProfiles</key>
    <dict>
        <key>com.change.wg</key>        <string>5M8LCZCTTU iOS App Store</string>
        <key>com.change.wg.tunnel</key> <string>TFR5M8FZMC iOS App Store</string>
    </dict>
    <key>stripSwiftSymbols</key>  <true/>
    <key>destination</key>        <string>export</string>
</dict>
</plist>
PLIST

# ── 4. Manually re-sign the archive's .app + package as .ipa ───────────
# Xcode 26's exportArchive runs an opaque "Copy failed" before the
# packaging completes, so we bypass it: codesign the .app with the
# Distribution cert + downloaded provisioning profiles, then zip into
# .ipa structure by hand. This is what altool would do internally.
banner "manual re-sign + repackage → $EXPORT_DIR"
rm -rf "$EXPORT_DIR" && mkdir -p "$EXPORT_DIR"

APP_SRC="$ARCHIVE_PATH/Products/Applications/WireGuardSampleApp-iOS.app"
PAYLOAD="$EXPORT_DIR/Payload"
mkdir -p "$PAYLOAD"
cp -R "$APP_SRC" "$PAYLOAD/"
APP="$PAYLOAD/WireGuardSampleApp-iOS.app"
APPEX="$APP/PlugIns/WireGuardTunnelExtension-iOS.appex"

# Drop the new profiles into the bundles
cp "$HOME/Library/MobileDevice/Provisioning Profiles/f95339bd-99c9-46b8-bbef-0084e44e876f.mobileprovision" "$APP/embedded.mobileprovision"
cp "$HOME/Library/MobileDevice/Provisioning Profiles/3f0988c6-f133-452b-a271-883b3df4d17c.mobileprovision" "$APPEX/embedded.mobileprovision"

# Build entitlements for codesign from the PROJECT's .entitlements
# files (the canonical set we want), NOT from the profile (which
# includes every capability Apple offers for that bundle ID — like
# icloud-services='*' that iOS rejects at upload time, 90046).
cp "$PROJECT_ROOT/WireGuardSampleApp-iOS/WireGuardSampleApp.entitlements"     "$EXPORT_DIR/app.entitlements"
cp "$PROJECT_ROOT/WireGuardTunnelExtension-iOS/WireGuardTunnelExtension.entitlements" "$EXPORT_DIR/appex.entitlements"

# Layer in the team-prefixed application-identifier + team-identifier
# that every signed iOS bundle needs at distribution. plistlib makes
# this idempotent (replace-or-insert in one call) without plutil's
# silent-failure modes.
python3 - "$EXPORT_DIR/app.entitlements"   "$TEAM_ID.com.change.wg"        "$TEAM_ID" <<'PY'
import plistlib, sys
path, app_id, team = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, 'rb') as f: d = plistlib.load(f)
d['application-identifier'] = app_id
d['com.apple.developer.team-identifier'] = team
with open(path, 'wb') as f: plistlib.dump(d, f)
PY
python3 - "$EXPORT_DIR/appex.entitlements" "$TEAM_ID.com.change.wg.tunnel" "$TEAM_ID" <<'PY'
import plistlib, sys
path, app_id, team = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, 'rb') as f: d = plistlib.load(f)
d['application-identifier'] = app_id
d['com.apple.developer.team-identifier'] = team
with open(path, 'wb') as f: plistlib.dump(d, f)
PY

DIST_CERT="Apple Distribution: XiangBo Kong (Z9XG3YEP93)"

# Re-sign appex first (codesign needs nested bundles signed first)
/usr/bin/codesign --force --sign "$DIST_CERT" --timestamp \
    --entitlements "$EXPORT_DIR/appex.entitlements" \
    --generate-entitlement-der "$APPEX"

# Sign WireGuardCore.framework if present (re-sign all nested frameworks)
for fw in "$APP"/Frameworks/*.framework "$APP"/Frameworks/*.dylib; do
    [[ -e "$fw" ]] || continue
    /usr/bin/codesign --force --sign "$DIST_CERT" --timestamp "$fw"
done

# Sign the main app
/usr/bin/codesign --force --sign "$DIST_CERT" --timestamp \
    --entitlements "$EXPORT_DIR/app.entitlements" \
    --generate-entitlement-der "$APP"

# Verify
/usr/bin/codesign --verify --deep --strict --verbose=2 "$APP" 2>&1 | tail -5

# Package into .ipa
IPA_PATH="$EXPORT_DIR/$SCHEME.ipa"
(cd "$EXPORT_DIR" && zip -qr "$IPA_PATH" Payload)
rm -rf "$PAYLOAD"

banner ".ipa ready"
ls -lh "$IPA_PATH"

if [[ $SKIP_UPLOAD -eq 1 ]]; then
    echo
    echo "--skip-upload set; stopping here."
    echo "ipa: $IPA_PATH"
    exit 0
fi

# ── 5. Upload gate ─────────────────────────────────────────────────────
banner "Upload to App Store Connect?"
cat <<INFO
  target    TestFlight (public-beta candidate)
  ipa       $IPA_PATH
  version   $VERSION  build  $BUILD  sha  $SHA
  key_id    $ASC_KEY_ID
  issuer    $ASC_ISSUER_ID
  key_path  $ASC_KEY_PATH

Irreversible: CFBundleVersion ($BUILD) must monotonically increase for
every future upload. External TestFlight's first build also triggers
Beta App Review (~24h).
INFO

[[ -f "$ASC_KEY_PATH" ]] || fail "API key .p8 not found at $ASC_KEY_PATH — drop AuthKey_$ASC_KEY_ID.p8 there or set ASC_KEY_PATH"

if [[ $AUTO_YES -eq 0 ]]; then
    read -r -p "Proceed with upload? [y/N] " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || { echo "Aborted. ipa preserved at $IPA_PATH."; exit 0; }
fi

# ── 6. Upload via altool (bypass xcodebuild's broken pipeline) ─────────
# `xcrun altool --upload-app -f <ipa> --apiKey K --apiIssuer I` is
# what Transporter.app / Xcode Organizer use under the hood. Same
# auth as the rest of this script.
banner "xcrun altool --upload-app"
xcrun altool --upload-app \
    -f "$IPA_PATH" \
    -t ios \
    --apiKey "$ASC_KEY_ID" \
    --apiIssuer "$ASC_ISSUER_ID" 2>&1 | tail -15

banner "Done"
cat <<NEXT
✓ Uploaded WireGuard $VERSION ($BUILD) · sha $SHA

Next steps in App Store Connect:
  1. Wait for "Processing" → TestFlight build list shows the new row
     (10-30 min for first upload of a marketing version).
  2. Fill Test Information (what to test, contact email, review notes).
  3. External Testing → add to a group with a Public Link enabled.

Artifacts kept at:
  archive  $ARCHIVE_PATH
  ipa      $IPA_PATH
NEXT
