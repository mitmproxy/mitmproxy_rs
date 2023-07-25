#!/usr/bin/env bash

set -eou pipefail

# check if BUILD_CERTIFICATE_BASE64 is set
if [ -n "$BUILD_CERTIFICATE_BASE64" ]; then
  echo "Signing keys available, building signed binary..."

  # Create variables
  CERTIFICATE_PATH=$RUNNER_TEMP/build_certificate.p12
  PP_PATH=$RUNNER_TEMP/build_pp.provisionprofile
  PPE_PATH=$RUNNER_TEMP/build_ppe.provisionprofile
  KEYCHAIN_PATH=$RUNNER_TEMP/app-signing.keychain-db

  # Import certificate and provisioning profile from secrets
  echo -n "$BUILD_CERTIFICATE_BASE64" | base64 --decode -o $CERTIFICATE_PATH
  echo -n "$BUILD_PROVISION_PROFILE_BASE64" | base64 --decode -o $PP_PATH
  echo -n "$BUILD_PROVISION_PROFILE_EXTENSION_BASE64" | base64 --decode -o $PPE_PATH

  # Create temporary keychain
  security create-keychain -p "app-signing" $KEYCHAIN_PATH
  security set-keychain-settings -lut 21600 $KEYCHAIN_PATH
  security unlock-keychain -p "app-signing" $KEYCHAIN_PATH

  # Import certificate to keychain
  security import $CERTIFICATE_PATH -P "$P12_PASSWORD" -A -t cert -f pkcs12 -k $KEYCHAIN_PATH
  security list-keychain -d user -s $KEYCHAIN_PATH

  # Apply provisioning profile
  mkdir -p ~/Library/MobileDevice/Provisioning\ Profiles
  cp $PP_PATH ~/Library/MobileDevice/Provisioning\ Profiles
  cp $PPE_PATH ~/Library/MobileDevice/Provisioning\ Profiles

  xcodebuild -project macos-redirector/MitmproxyAppleTunnel.xcodeproj -destination 'platform=macOS' CODE_SIGN_IDENTITY="Apple Development: Maximilian Hils (N72CKJ646S)" OTHER_CODE_SIGN_FLAGS="--keychain $KEYCHAIN_PATH" PROVISIONING_PROFILE="$PPE_PATH" -scheme MitmproxyAppleExtension build
  xcodebuild -project macos-redirector/MitmproxyAppleTunnel.xcodeproj -destination 'platform=macOS' CODE_SIGN_IDENTITY="Apple Development: Maximilian Hils (N72CKJ646S)" OTHER_CODE_SIGN_FLAGS="--keychain $KEYCHAIN_PATH" PROVISIONING_PROFILE="$PP_PATH" -scheme MitmproxyAppleTunnel build
else
  echo "Signing keys not available, building unsigned binary..."
  xcodebuild -project macos-redirector/MitmproxyAppleTunnel.xcodeproj -destination 'platform=macOS' CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED="NO" CODE_SIGN_ENTITLEMENTS="" CODE_SIGNING_ALLOWED="NO" -scheme MitmproxyAppleExtension build
  xcodebuild -project macos-redirector/MitmproxyAppleTunnel.xcodeproj -destination 'platform=macOS' CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED="NO" CODE_SIGN_ENTITLEMENTS="" CODE_SIGNING_ALLOWED="NO" -scheme MitmproxyAppleTunnel build
fi
