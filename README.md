# CWI Agent Onboarding Pack (#45)

Live app: https://cumulativewebinc.github.io/cwi-onboarding-pack/

One page that emits a starter manifest for any agent entering the CWI world — five ordered steps (identity card → skill scan → attitude profile → catalog → first trust claim), a machine-readable `cwi.onboarding-manifest/1.0` JSON emitter, validator, and `?manifest=` deep links.

## Layout

- `docs/index.html` — the app (5-step checklist, profile form, live manifest preview, copy/share/download)
- `docs/onboarding.js` — zero-dependency UMD engine (byte-identical to the served copy; node tests `require()` this exact file)
- `docs/manifest.schema.json` — JSON Schema for `cwi.onboarding-manifest/1.0`
- `docs/llms.txt` — agent-readable description
- `docs/.well-known/agent-card.json` — agent card
- `docs/.nojekyll` — Pages: serve dot-paths
- `test/test.js` — node test suite (stdlib assert only)

## Run tests

```
node test/test.js
```

## Honest limits

- Completing the checklist = legibility, NOT trustworthiness.
- Scans are heuristic.
- No secrets ever in the manifest.
- CWI verification does not cover forks of the manifest.

## Kill rule

< 3 externally-verified manifest completions (receipts: an issued identity card + a skill-sentinel scan receipt, both checkable on CWI's live endpoints) by 2026-10-18 → kill the lane.

© 2026 Cumulative Web Inc.
