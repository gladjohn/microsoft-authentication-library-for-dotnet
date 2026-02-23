# TESTING.md — MSI v2 Log Triage

This document describes how to run the log-triage analyzer locally and how to
trigger the GitHub Actions workflow manually for end-to-end verification.

---

## Local Setup

### Prerequisites

- [Node.js](https://nodejs.org/) 18 or later
- npm (bundled with Node.js)

### Install Dependencies

```bash
cd .github/msal-log-triage
npm install
```

### Run Unit Tests

```bash
# inside .github/msal-log-triage/
npm test
```

All 37 tests should pass.  To view coverage:

```bash
npm run test:coverage
```

### Run the Analyzer Interactively

You can pass any MSAL log file through the analyzer from a Node.js REPL:

```js
const { analyze } = require('./index.js');
const fs = require('fs');

const body = fs.readFileSync('./__tests__/data/issue-5755-mtls-schannel.log', 'utf8');
const result = analyze(body);
console.log(JSON.stringify(result, null, 2));
```

Expected output includes:

```json
{
  "isMiV2": true,
  "stages": [
    {
      "stage": "mtls_schannel",
      "label": "mTLS / SCHANNEL",
      "severity": "error",
      ...
    }
  ],
  "labels": ["msi-v2:triage-run", "msi-v2:has-failure"],
  ...
}
```

---

## Test Data Samples

| File | Description |
|---|---|
| `__tests__/data/issue-5755-mtls-schannel.log` | mTLS + SCHANNEL error (mirrors real issue #5755) |
| `__tests__/data/cache-hit-miss.log` | Token cache hit and cache miss flow |
| `__tests__/data/imds-failure.log` | IMDS endpoint unreachable |
| `__tests__/data/non-miv2.log` | Public-client log — should **not** trigger triage |

---

## Manual Workflow Test (GitHub Actions)

1. Open (or edit) an issue in the repository whose body contains one of the
   MSI v2 gating keywords:
   - `ManagedIdentityV2`
   - `MiV2`
   - `MI V2`
   - `mi-v2`
   - `MIv2`

   Or apply the `scenario:ManagedIdentity` label to an existing issue.

2. Navigate to **Actions → MSI v2 Log Triage** to confirm the workflow was
   triggered.

3. After the run completes, verify:
   - A triage comment starting with `## 🔍 MSI v2 Automated Log Triage` was
     posted on the issue.
   - The labels `msi-v2:triage-run` (and `msi-v2:has-failure` if errors were
     found) were applied.
   - Re-editing the issue replaces the existing triage comment instead of
     creating a duplicate (look for `<!-- msal-log-triage-bot -->` in the raw
     comment body).

---

## Signature Rules

Failure patterns are stored in [`signatures.yml`](./signatures.yml).  Adding a
new stage requires:

1. Add a new top-level key under `stages` in `signatures.yml`.
2. Add corresponding test cases in `__tests__/analyzer.test.js`.
3. Run `npm test` to confirm all tests pass.
