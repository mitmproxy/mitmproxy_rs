#!/usr/bin/env bash

set -eou pipefail

if [ -n "${APPLE_ID+x}" ]; then
  echo "Signing keys available, building signed binary..."

  APPLE_TEAM_ID=S8XHQB96PW

  # Install provisioning profiles
  mkdir -p ~/Library/MobileDevice/Provisioning\ Profiles
  echo -n "$APPLE_PROVISIONING_PROFILE_APP" | base64 --decode -o ~/Library/MobileDevice/Provisioning\ Profiles/app.provisionprofile
  echo -n "$APPLE_PROVISIONING_PROFILE_EXT" | base64 --decode -o ~/Library/MobileDevice/Provisioning\ Profiles/ext.provisionprofile

  ## Exported from keychain to .p12 and then
  ## openssl pkcs12 -in key.p12 -nodes -legacy
  security import <(echo -n "$APPLE_CERTIFICATE") -A
  security unlock-keychain

  mkdir build
  xcodebuild \
    -scheme macos-redirector \
    -archivePath build/macos-redirector.xcarchive \
    archive
  xcodebuild \
    -exportArchive \
    -archivePath build/macos-redirector.xcarchive \
    -exportOptionsPlist ./ExportOptions.plist \
    -exportPath ./build

  # Notarize
  # https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution/customizing_the_notarization_workflow
  xcrun notarytool store-credentials "AC_PASSWORD" \
    --apple-id "$APPLE_ID" \
    --team-id "$APPLE_TEAM_ID" \
    --password "$APPLE_APP_PASSWORD"
  ditto -c -k --keepParent "./build/Mitmproxy Redirector.app" "./build/Mitmproxy Redirector.zip"
  xcrun notarytool submit \
    "./build/Mitmproxy Redirector.zip" \
    --keychain-profile "AC_PASSWORD" \
    --wait
  xcrun stapler staple "./build/Mitmproxy Redirector.app"

  mv "./build/Mitmproxy Redirector.app" "./dist/Mitmproxy Redirector.app"
else
  echo "Signing keys not available, building unsigned binary..."
  xcodebuild -scheme macos-redirector CODE_SIGNING_ALLOWED="NO" build
fi
