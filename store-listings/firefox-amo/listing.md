# Firefox AMO Listing Copy

## Add-on Name
SSHKey Web Auth

## Summary
SSH public-key authentication helper for compatible login pages, with local native signing.

## Description
SSHKey Web Auth enables SSH challenge-response login flows in web apps that expose compatible form fields.

This add-on:
- reads challenge + namespace from login form hidden fields
- enforces origin allowlist and per-origin namespace mapping
- sends challenge to a local native host (`com.pubkey.auth`)
- signs via `ssh-keygen -Y sign`
- writes signature to form and submits

Reusable for any site that implements compatible SSH challenge fields and verification flow.

Links:
- Extension repo: https://github.com/daniel-alexander4/sshkey-web-auth

## Data Collection Disclosure
No telemetry or analytics are collected by this add-on.
Settings are stored locally in browser extension storage.
Signing is performed locally through system SSH tooling.

## Permissions Explanation
- `storage`: save local user config.
- `nativeMessaging`: communicate with native helper.
- host permissions for localhost/127.0.0.1 over http/https.

## Reviewer Instructions
1. Load signed add-on in Firefox.
2. Install native host manifest for Firefox:
   - `~/.mozilla/native-messaging-hosts/com.pubkey.auth.json`
3. Open add-on preferences and set:
   - Allowed origins: `http://localhost:8080`
   - Origin namespaces: `http://localhost:8080 myapp`
4. Visit compatible login page at `http://localhost:8080/login`.
5. Enter username and click Login.
6. Confirm challenge is signed and form submits.

## Support URL
https://github.com/daniel-alexander4/sshkey-web-auth/issues
