#!/bin/bash

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
security create-keychain -p "$KEYCHAIN_PASSWORD" $KEYCHAIN_PATH
security set-keychain-settings -lut 21600 $KEYCHAIN_PATH
security unlock-keychain -p "$KEYCHAIN_PASSWORD" $KEYCHAIN_PATH

# Import certificate to keychain
security import $CERTIFICATE_PATH -P "$P12_PASSWORD" -A -t cert -f pkcs12 -k $KEYCHAIN_PATH
security list-keychain -d user -s $KEYCHAIN_PATH

# Apply provisioning profile
mkdir -p ~/Library/MobileDevice/Provisioning\ Profiles
cp $PP_PATH ~/Library/MobileDevice/Provisioning\ Profiles
cp $PPE_PATH ~/Library/MobileDevice/Provisioning\ Profiles

# Clean up DerivedData
rm -rf ~/Library/Developer/Xcode/DerivedData
