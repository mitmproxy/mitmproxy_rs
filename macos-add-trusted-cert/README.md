# Why we have to create a Bundle App to add and trust the certificate

This minimal bundle app is to overcome the limitations of macOS in automating the mitmproxy certificate installation and trust process. This app will operate without any user interaction or window display, except for the possible popup asking for permission to unlock the keychain. By bypassing the GUI restrictions, this solution ensures smoother and automated certificate management on MacOS systems.

Read the [Special Consideration](https://developer.apple.com/documentation/security/1399119-sectrustsettingssettrustsettings#1819554) paragraph on official Apple Documentation for more info.
