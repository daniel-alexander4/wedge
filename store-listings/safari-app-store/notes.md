# Safari App Store Notes

Safari distribution requires packaging as a Safari Web Extension app via Xcode.

## Positioning Copy
SSHKey Web Auth brings SSH challenge-signing login support to compatible web apps, using local system SSH keys and explicit per-origin namespace policy.

## Important Constraints
- Safari extension is distributed as part of a macOS app package.
- Native messaging and local host behavior may differ from Chromium/Firefox and must be validated with Safari-specific implementation details.
- Provide clear install/setup docs for any required local helper tooling.

## App Store Metadata Draft
- App name: SSHKey Web Auth
- Subtitle: SSH key login helper
- Keywords: ssh, authentication, webextension, developer, login
- Support URL: https://github.com/daniel-alexander4/sshkey-web-auth/issues
- Marketing URL: https://github.com/daniel-alexander4/sshkey-web-auth

## Review Notes
- Explain that signing is local and uses system SSH tools.
- Explain required user configuration for allowed origins and origin namespaces.
