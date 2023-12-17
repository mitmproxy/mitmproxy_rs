#!/usr/bin/env bash

set -eou pipefail

if [ -n "${APPLE_ID-}" ]; then
  echo "Signing keys available, building signed binary..."

  APPLE_TEAM_ID=S8XHQB96PW

  # Install provisioning profiles
  mkdir -p ~/Library/MobileDevice/Provisioning\ Profiles
  echo -n "$APPLE_PROVISIONING_PROFILE_APP" | base64 --decode -o ~/Library/MobileDevice/Provisioning\ Profiles/app.provisionprofile
  echo -n "$APPLE_PROVISIONING_PROFILE_EXT" | base64 --decode -o ~/Library/MobileDevice/Provisioning\ Profiles/ext.provisionprofile

  # Create temporary keychain
  KEYCHAIN_PATH=$RUNNER_TEMP/app-signing.keychain
  security create-keychain -p "app-signing" $KEYCHAIN_PATH
  security set-keychain-settings -lut 21600 $KEYCHAIN_PATH
  security unlock-keychain -p "app-signing" $KEYCHAIN_PATH
  # Import certificate to keychain
  security import <(echo -n "$APPLE_CERTIFICATE") -A -k $KEYCHAIN_PATH
  security list-keychain -s $KEYCHAIN_PATH

  mkdir build
  xcodebuild \
    -scheme macos-redirector \
    -archivePath build/macos-redirector.xcarchive \
    OTHER_CODE_SIGN_FLAGS="--keychain $KEYCHAIN_PATH" \
    archive
  xcodebuild \
    -exportArchive \
    -archivePath build/macos-redirector.xcarchive \
    -exportOptionsPlist ./ExportOptions.plist \
    -exportPath ./build

  # Notarize
  # https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution/customizing_the_notarization_workflow
  xcrun notarytool store-credentials "AC_PASSWORD" \
    --keychain "$KEYCHAIN_PATH" \
    --apple-id "$APPLE_ID" \
    --team-id "$APPLE_TEAM_ID" \
    --password "$APPLE_APP_PASSWORD"
  ditto -c -k --keepParent "./build/Mitmproxy Redirector.app" "./build/Mitmproxy Redirector.zip"
  xcrun notarytool submit \
    "./build/Mitmproxy Redirector.zip" \
    --keychain "$KEYCHAIN_PATH" \
    --keychain-profile "AC_PASSWORD" \
    --wait
  xcrun stapler staple "./build/Mitmproxy Redirector.app"

  mkdir -p dist
  tar --create --file "./dist/Mitmproxy Redirector.app.tar" --cd "./build" "Mitmproxy Redirector.app"
else
  echo "Signing keys not available, building unsigned binary..."
  xcodebuild -scheme macos-redirector CODE_SIGNING_ALLOWED="NO" build
  mkdir -p dist
  touch "dist/Mitmproxy Redirector.app.tar"
fi
