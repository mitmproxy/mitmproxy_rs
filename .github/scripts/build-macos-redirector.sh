#!/usr/bin/env bash

set -eou pipefail

if [ -n "${APPLE_ID+x}" ]; then
  echo "Signing keys available, building signed binary..."

  APPLE_TEAM_ID=S8XHQB96PW

  # Install provisioning profiles
  mkdir -p ~/Library/MobileDevice/Provisioning\ Profiles
  echo -n "$APPLE_PROVISIONING_PROFILE_APP" | base64 --decode -o ~/Library/MobileDevice/Provisioning\ Profiles/app.mobileprovision
  echo -n "$APPLE_PROVISIONING_PROFILE_EXT" | base64 --decode -o ~/Library/MobileDevice/Provisioning\ Profiles/ext.mobileprovision

  # Exported from keychain to .p12 and then
  # openssl pkcs12 -in key.p12 -nodes -legacy
  security import <(echo -n "$APPLE_CERTIFICATE") -A
#
#  echo "a"
#  security list-keychain
#  echo "b"
#  security list-keychain -d user
#
#  KEYCHAIN_PATH=$RUNNER_TEMP/app-signing.keychain-db
#  security create-keychain -p "app-signing" $KEYCHAIN_PATH
#  security set-keychain-settings -lut 21600 $KEYCHAIN_PATH
#  security unlock-keychain -p "app-signing" $KEYCHAIN_PATH
#  security import <(echo -n "$APPLE_CERTIFICATE" | base64 --decode) \
#    -A -t cert -k $KEYCHAIN_PATH
#  echo "c"
#  security list-keychain -s $KEYCHAIN_PATH
#  echo "d"
#  security list-keychain -d user -s $KEYCHAIN_PATH
#
#  echo "e"
#  security dump-keychain

#  echo -n "$APPLE_CERTIFICATE" | base64 --decode -o  "$RUNNER_TEMP/build.cer"
#  ls -l "$RUNNER_TEMP"
#  # security import "$RUNNER_TEMP/build.cer" -A -t cert
#
#
#  # create temporary keychain
#  KEYCHAIN_PATH=$RUNNER_TEMP/app-signing.keychain-db
#  security create-keychain -p "app-signing" $KEYCHAIN_PATH
#  security set-keychain-settings -lut 21600 $KEYCHAIN_PATH
#  security unlock-keychain -p "app-signing" $KEYCHAIN_PATH
#
#  # import certificate to keychain
#  security import "$RUNNER_TEMP/build.cer" -P "$P12_PASSWORD" -A -t cert -f pkcs12 -k $KEYCHAIN_PATH
#  security list-keychain -d user -s $KEYCHAIN_PATH

  # ls -l "~/Library/MobileDevice/Provisioning Profiles/"

  mkdir build
  xcodebuild \
    -scheme macos-redirector \
    -target macos-redirector \
    -destination 'platform=macOS' \
    -archivePath build/macos-redirector.xcarchive \
    -configuration Release \
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

#
#  # Create variables
#  CERTIFICATE_PATH=$RUNNER_TEMP/build_certificate.p12
#  PP_PATH=$RUNNER_TEMP/build_pp.provisionprofile
#  PPE_PATH=$RUNNER_TEMP/build_ppe.provisionprofile
#  KEYCHAIN_PATH=$RUNNER_TEMP/app-signing.keychain-db
#
#  # Import certificate and provisioning profile from secrets
#  echo -n "$BUILD_CERTIFICATE_BASE64" | base64 --decode -o $CERTIFICATE_PATH
#  echo -n "$BUILD_PROVISION_PROFILE_BASE64" | base64 --decode -o $PP_PATH
#  echo -n "$BUILD_PROVISION_PROFILE_EXTENSION_BASE64" | base64 --decode -o $PPE_PATH
#
#  # Create temporary keychain
#  security create-keychain -p "app-signing" $KEYCHAIN_PATH
#  security set-keychain-settings -lut 21600 $KEYCHAIN_PATH
#  security unlock-keychain -p "app-signing" $KEYCHAIN_PATH
#
#  # Import certificate to keychain
#  security import $CERTIFICATE_PATH -P "$P12_PASSWORD" -A -t cert -f pkcs12 -k $KEYCHAIN_PATH
#  security list-keychain -d user -s $KEYCHAIN_PATH
#
#  # Apply provisioning profile
#  mkdir -p ~/Library/MobileDevice/Provisioning\ Profiles
#  cp $PP_PATH ~/Library/MobileDevice/Provisioning\ Profiles
#  cp $PPE_PATH ~/Library/MobileDevice/Provisioning\ Profiles
#
#  xcodebuild -project macos-redirector/MitmproxyAppleTunnel.xcodeproj -destination 'platform=macOS' CODE_SIGN_IDENTITY="Apple Development: Maximilian Hils (N72CKJ646S)" OTHER_CODE_SIGN_FLAGS="--keychain $KEYCHAIN_PATH" PROVISIONING_PROFILE="$PPE_PATH" -scheme MitmproxyAppleExtension build
#  xcodebuild -project macos-redirector/MitmproxyAppleTunnel.xcodeproj -destination 'platform=macOS' CODE_SIGN_IDENTITY="Apple Development: Maximilian Hils (N72CKJ646S)" OTHER_CODE_SIGN_FLAGS="--keychain $KEYCHAIN_PATH" PROVISIONING_PROFILE="$PP_PATH" -scheme MitmproxyAppleTunnel build
else
  echo "Signing keys not available, building unsigned binary..."
  xcodebuild -scheme macos-redirector CODE_SIGNING_ALLOWED="NO" build
fi
