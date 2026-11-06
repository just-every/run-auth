# sx-auth-f42regen-2 results

Repository: just-every/run-auth (treated as public).
Product branch: cloud/sx-auth-f42regen-2.
Product head: d55816c1f0e6b66f12d0c2846fdba6cf22965251.
Base: 2155ce890f326586fc859423ab2cfa5343e3a983, current main at clone time.
Verified source: cloud/sx-auth-c-f42 at 62ea73a0363d994ebc3535fcd703434c8cdf5820.
PR: none; repository Verify accepts branch pushes and the fleet lander retains landing custody.

## Implementation and replay

Applied the product changes of 713905bcfc35c52a24fc4f521eb9126edbe62ea4, b9acf9c2d46bc47c2a55d9495c99426d2db642c1 and 62ea73a0363d994ebc3535fcd703434c8cdf5820 onto main. The first no-commit cherry-pick conflicted only on sources.lock.json. Stopped that sequencer, restored main's CONTRACT.md and source lock, and applied the remaining product delta with a three-way patch. No published history was rewritten. The final source lock was generated afresh after validation.

The native group inspect and effective-grant tools now resolve validated native group audit targets. The production journey includes single-group and removed-grant fixtures and target assertions. The unchanged f42 native test covers autonomous, held and read-approval policy, later-page groups, scoped visibility, policy-blocked/unset and self-escalation decisions, approved receipt replay after read-grant revocation, absent/deleted groups and membership side effects and refusals.

Regenerated docs/agents.md using node scripts/agent-docs.mjs write. Its new single-group and removed-grant fixtures and JSON-pointer references match agent-surface.json. The script writes only this guide. No UI layout or workflow changed; no test was deleted, weakened or skipped. Current main's newer native schemas, tests, assertions and other docs were retained.

## Validation

- Frozen dependency install: success; pnpm 10.12.4. Provided toolchain used Node 24.19.0; rer setup/build used its managed Node 22.20.0. Typecheck and direct tests passed under Node 24.19.0 despite the engine warning. Exact-SHA CI uses pinned Node 22.20.0.
- Noninteractive local setup with fleet owner email: exit 0. No external deployment performed and no local secret files selected for evidence.
- node scripts/agent-docs.mjs write and check: pass.
- node scripts/contract-docs.mjs write BASE-AGENT-009 and check BASE-AGENT-009: pass, 105 clauses and 23 metadata blocks. Restored ACCEPTANCE.md and docs/CLAIMS.md whole from origin/main afterward.
- pnpm run build: one explicit invocation, exit 0; production guide guard passes. Setup also built its runtime as part of setup; the site test built only the site.
- node --test --test-concurrency=1 tests/agent-door/audit-targets.test.mjs tests/site/run-site.test.mjs: 2 tests passed, 0 failed, 0 skipped. The rendered guide agrees with production tools/list (10 tool headings), 3 resource templates and the production class fixture journey. Missing, extra and stale metadata refusals remain asserted.
- pnpm run typecheck: exit 0.
- node scripts/edition-authoring/cli.mjs lock run last; pnpm check:sources: exit 0; 1075 source entries, no copied-Base drift or unrecorded copies.
- git diff --check: pass. Product tree clean. Only six intended files committed. CONTRACT.md, ACCEPTANCE.md and docs/CLAIMS.md are byte-identical to main.
- Active fleet commit-msg hook preserves repository hooks. Every product candidate author and committer is Run Edit Run fleet <fleet@runeditrun.com>. No trailers.
- Product push succeeded on its first attempt via cloud-push.py; one product push, no main push, no force push, no workflow dispatch or rerun.

## Clause counts and claims

Before and after: 37 done / 51 partial / 17 missing / 105 total. No clause status, Gap or Evidence changed. BASE-AGENT-009 remains partial.

The original fleet terminal log was not shipped and refs/heads/evidence/sx-auth-c-f42 was absent. CLAIM.md explicitly reconstructs the proposed native-audit evidence from the verified source diff; it does not claim to have recovered the original terminal CLAIM lines. No missing ruling was inferred. Existing custody and account holds remain intact.

CLAIM BASE-AGENT-009: partial -> partial; native group targets reconcile reads, held reads, effects and private refusals against independently read directory records, with live read-grant checks for fresh calls and approved receipt replay. This is evidence for the lane to review, not a builder promotion or complete audit acceptance.

## Custody and evidence

Full plan: PLAN.md. Actual build, touched-test, typecheck, guide, contract-generation, source-lock and source-check logs and structured receipts are included in this report-only packet. All selections are explicit regular files. No credentials, environment dump, private held-out gate material or symlinks are selected. Evidence publication uses only refs/heads/evidence/sx-auth-f42regen-2, outside the product branch.

Exact-SHA Verify status is recorded below. The previous failed lander Verify 42279121596 is historical context only, never used as current green proof.

## Final exact-SHA result

Verify Auth 42288166295: completed/success on d55816c1f0e6b66f12d0c2846fdba6cf22965251.
https://github.com/just-every/run-auth/actions/runs/42288166295

Four GitHub API calls total, one watcher, with at least 300 seconds between discovery and subsequent polls. No workflow was dispatched or rerun, and no historical SHA was used as green proof. No special generated-view exception was needed. No blocker remains. No PR was created or required by the repository guide. The product branch was pushed once and main was never changed.

READY branch=cloud/sx-auth-f42regen-2 head=d55816c1f0e6b66f12d0c2846fdba6cf22965251

POST lanes/sx/INBOX.md: sx-auth-f42regen-2 reapplied f42 on main and regenerated docs/agents.md; head=d55816c1f0e6b66f12d0c2846fdba6cf22965251; Verify Auth 42288166295 completed/success; counts unchanged 37 done/51 partial/17 missing (105 total); BASE-AGENT-009 remains partial; CLAIM native group target/read-authority-loss evidence for lane review; no contract metadata edited, no blockers.
