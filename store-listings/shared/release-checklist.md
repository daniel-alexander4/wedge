# Release Checklist

## 1) Version + Manifest Gate
- Set version in `package.json`, `manifests/manifest.chrome.json`, and `manifests/manifest.firefox.json`.
- Verify extension name, description, and icons are final.
- Confirm Firefox temporary-load compatibility (`manifest_version: 3` + `action`).
- Run:
  - `npm run typecheck`
  - `npm run test`
  - `npm run build:all`

## 2) Native Host Distribution Gate
- Decide production distribution path for native host:
  - Linux package (`.deb`/`.rpm`) or signed installer script wrapper.
  - macOS installer (`.pkg`) if Safari/Chrome macOS is targeted.
  - Windows installer (`.msi`) if Edge/Chrome Windows is targeted.
- Ensure installer registers `com.pubkey.auth` manifests for each browser channel.
- Ensure Chromium manifest `allowed_origins` uses production extension ID.
- Ensure Firefox manifest `allowed_extensions` uses production add-on ID.
- Smoke test native host after clean install:
  - extension can call native host
  - key path validation messages are clear
  - signing works end-to-end

## 3) Store Listing Assets Gate
- Prepare screenshots for:
  - extension popup/options
  - supported login page flow (`/login` -> signed submit)
  - error guidance (origin/namespace mismatch)
- Prepare required icons/promotional graphics per store dimensions.
- Finalize listing copy from:
  - `store-listings/chrome-web-store/listing.md`
  - `store-listings/firefox-amo/listing.md`
  - `store-listings/microsoft-edge-addons/listing.md`
  - `store-listings/safari-app-store/notes.md`

## 4) Policy + Metadata Gate
- Publish and link a public privacy/data-use page.
- Publish and link support URL + issue tracker URL.
- Document permissions justification:
  - `storage`
  - `nativeMessaging`
  - host permissions (`localhost`/`127.0.0.1` patterns)
- Confirm no telemetry/data collection claims are accurate.
- Confirm license is MIT in repo and listing text where referenced.

## 5) Reviewer Test Plan Gate
- Provide reviewer account-free test steps:
  - install extension
  - install helper/native host
  - configure `Origin namespaces` line (`<origin> <namespace>`)
  - open demo login page and authenticate
- Include known-good local demo values:
  - origin example: `http://127.0.0.1:18080`
  - namespace example: `myapp`
- Include failure-path examples and expected messages.

## 6) Browser Submission Gate
- Chrome Web Store:
  - package upload from `dist/chrome`
  - verify policy fields + support/privacy URLs
- Firefox AMO:
  - upload from `dist/firefox`
  - validate browser action visibility + options page
- Edge Add-ons:
  - submit Chromium package
  - verify metadata parity with Chrome listing
- Safari:
  - wrap via Safari Web Extension app in Xcode
  - complete App Store metadata + signing

## 7) Post-Publish Gate
- Tag Git release and include changelog + migration notes.
- Verify live install works on clean VM/user profile.
- Monitor issues and store review feedback:
  - https://github.com/daniel-alexander4/sshkey-web-auth/issues
- Prepare rollback plan:
  - previous package retained
  - emergency update procedure documented
