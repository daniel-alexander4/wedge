# Chrome Web Store Listing Copy

## Product Name
SSHKey Web Auth

## Short Description (132 chars max)
SSH public-key login extension with per-origin namespace policy and local native signing via ssh-keygen.

## Detailed Description
SSHKey Web Auth enables SSH public-key authentication workflows in web login forms.

Designed for secure challenge signing, this extension:
- reads login challenge fields from compatible pages
- validates origin and namespace policy
- signs challenges through a local native messaging host using `ssh-keygen -Y sign`
- fills the signature field and submits login

Security model highlights:
- per-origin allowlist (`Allowed origins`)
- per-origin namespace mapping (`Origin namespaces`)
- strict challenge format validation
- native host message-size limits

Important:
- This extension requires a local native messaging host (`com.pubkey.auth`) on the user machine.
- It does not upload private keys; signing happens locally via system `ssh-keygen`.

Project links:
- Extension repo: https://github.com/daniel-alexander4/sshkey-web-auth

## Category
Developer Tools

## Language
English

## Single Purpose Statement
Provide SSH challenge signing for web login flows using local system keys and explicit origin/namespace policy.

## Permissions Justification
- `storage`: save extension settings (enabled flag, native host name, key path, origin policy).
- `nativeMessaging`: communicate with local native host that calls `ssh-keygen`.
- host access (`localhost`, `127.0.0.1`, http/https): run content script on local web apps using this login flow.

## Privacy / Data Use Statement
SSHKey Web Auth stores configuration locally in browser extension storage.
Challenge text is sent only to the local native host on the same machine for signing.
No telemetry, analytics, or remote key upload is performed by the extension.

## Reviewer Test Instructions
1. Load unpacked extension from `dist/chrome`.
2. Install native host from `native-host/install-linux.sh` with this extension ID.
3. Open extension settings and configure:
   - Allowed origins: `http://localhost:8080`
   - Origin namespaces: `http://localhost:8080 myapp`
   - Key path: valid SSH private key path
4. Open compatible login page at `http://localhost:8080/login`.
5. Enter username and click Login.
6. Confirm signature auto-fills and form submits.

## Support URL
https://github.com/daniel-alexander4/sshkey-web-auth/issues
