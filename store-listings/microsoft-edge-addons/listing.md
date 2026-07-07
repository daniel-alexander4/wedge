# Microsoft Edge Add-ons Listing Copy

## Name
SSHKey Web Auth

## Summary
SSH public-key login extension with local challenge signing and per-origin namespace policy.

## Description
SSHKey Web Auth adds SSH challenge-signing support to compatible web login forms.

The extension works with any site that implements compatible SSH challenge fields and verification flow.

How it works:
- Detects compatible login form fields on allowed origins
- Reads `ssh_challenge` and `ssh_namespace`
- Validates site origin + expected namespace mapping
- Calls local native host (`com.pubkey.auth`) to sign with `ssh-keygen -Y sign`
- Fills signature and submits

Security controls:
- explicit `Allowed origins`
- explicit `Origin namespaces` mapping
- strict challenge validation
- local-only native signing path

Important requirement:
- A native messaging host must be installed on the local machine.

Project links:
- Extension: https://github.com/daniel-alexander4/sshkey-web-auth

## Permissions Rationale
- `storage`: save local configuration.
- `nativeMessaging`: connect to local host for signature generation.
- host permissions (`localhost`, `127.0.0.1`): run on local apps using this auth flow.

## Privacy Statement
Configuration is stored locally.
Signing is performed locally via system SSH tooling.
No remote transmission of private keys by the extension.

## Test Notes For Review
1. Install extension package.
2. Install native host and map to extension ID.
3. Configure:
   - Allowed origins: `http://localhost:8080`
   - Origin namespaces: `http://localhost:8080 myapp`
4. Open compatible login page and click Login after entering username.
5. Verify signature is produced and submitted.

## Support
https://github.com/daniel-alexander4/sshkey-web-auth/issues
