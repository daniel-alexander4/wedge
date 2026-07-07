# Contributing

## Local Setup

```bash
npm install
npm run typecheck
npm run test
npm run build:all
```

For debug logging in extension bundles:

```bash
DEBUG=true npm run build:all
```

## Before Opening a PR

Run and ensure all pass:

```bash
npm run typecheck
npm run test
npm run build:all
```

## Scope Notes

- Keep origin/namespace/company validation strict.
- Preserve the explicit login contract (`/login`, `auth-verify-form`, `login-submit-btn`) unless intentionally changing security boundaries.
- If native host behavior changes, update both docs and tests.
