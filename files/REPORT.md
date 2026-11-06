# sx-auth-f42regen-1

Status: BLOCKED. The source-identity prerequisite failed before product changes.

Repository: just-every/run-auth
Local checkout: /workspace/run-auth
Local branch: cloud/sx-auth-f42regen-1
Local product HEAD / current main: 2155ce890f326586fc859423ab2cfa5343e3a983
Expected source branch HEAD: 2d7346818d0dc5c0095b565688384dfc13c7dab7 (required prefix 2d734681)
Observed source branch HEAD: 62ea73a0363d994ebc3535fcd703434c8cdf5820

## Plan

1. Set fleet identity, refresh launcher credentials, install the bundle-only Git helper, inspect cloud networking and repository instructions.
2. Shallow filtered clone current main; fetch cloud/sx-auth-c-f42 and verify its head begins 2d734681 before applying any commit.
3. If source identity matches, replay f42 changes on cloud/sx-auth-f42regen-1 from current main, retain main's newer assertions, tests and docs, and omit CONTRACT.md Status, Gap and Evidence changes. Carry available CLAIM lines in the final report.
4. Regenerate docs/agents.md using node scripts/agent-docs.mjs write; check the guide and contract generator; leave ACCEPTANCE.md and docs/CLAIMS.md uncommitted.
5. Run pnpm run build once, the touched-file tests and typecheck. Regenerate sources.lock.json last and run pnpm check:sources. Keep hooks active and verify all candidate commit identities and trailers.
6. Commit the candidate and push the named product branch through cloud-push.py; observe exact-SHA Verify within the API budget. Publish the actual report and receipt separately on evidence/sx-auth-f42regen-1.

## Actual results

Fleet global/local identity configured; launcher refreshed successfully; decrypted-bundle-only Git credential helper installed; no embedded credential rewrites found. Cloud HTTP policy enforced and unrestricted. Repository AGENTS.md, CONTRACT.md and ACCEPTANCE.md inspected; contract source and view ownership rules retained. pnpm install --frozen-lockfile passed. Fleet commit-msg cleanup hooks installed after dependency setup; no commits created.

The fetch resolved cloud/sx-auth-c-f42 to 62ea73a0363d994ebc3535fcd703434c8cdf5820. A separate git ls-remote --heads confirmation returned the same full source SHA. This differs from the required 2d734681 prefix. No ruling authorizes using the updated source branch in place of the specified candidate. Replay, guide generation, build, tests, typecheck and source-lock regeneration therefore remain unexecuted, rather than verifying a different product candidate.

The requested branch was created locally from current main and has no changes or candidate commits. It has not been pushed. No product push was rejected. No workflows dispatched or rerun, no PR created, and no GitHub API calls spent. The historical Verify run 42279121596 is context from the assignment, not a result for this checkout. There is no exact-SHA CI result for a new candidate.

Before/after clause counts: {"done": 35, "missing": 17, "partial": 50} → {"done": 35, "missing": 17, "partial": 50}. No clause status, Gap or Evidence changes; BASE-AGENT-009 remains partial. No tests were modified, deleted or weakened; no workflow changed. The source branch's contract evidence edit was inspected but not applied.

## CLAIM custody

$HOME/rer-consolidation/logs/sx-auth-c-f42.last.txt was unavailable. refs/heads/evidence/sx-auth-c-f42 was absent in both the initial explicit fetch (remote ref not found) and the subsequent successful remote-ref listing. No CLAIM lines were available to carry; none were invented.

## Required next step

The lane must provide an updated ruling authorizing source HEAD 62ea73a0363d994ebc3535fcd703434c8cdf5820, or restore the source ref to the specified 2d7346818d0dc5c0095b565688384dfc13c7dab7, before replay and regeneration. This task preserves the existing product checkout and publishes only these non-secret evidence files. Evidence publication does not establish product READY or landing.
