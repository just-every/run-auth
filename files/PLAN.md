# sx-auth-f42regen-2 plan

1. Install fleet authentication, identity and preserving commit hooks. Shallow filtered clone only just-every/run-auth; verify source cloud/sx-auth-c-f42 is 62ea73a0363d994ebc3535fcd703434c8cdf5820.
2. Create cloud/sx-auth-f42regen-2 from current main. Apply the three f42 commits, retaining current main tests, docs and contract judgments. Drop all CONTRACT.md Status, Gap and Evidence edits. Keep generated ACCEPTANCE.md and docs/CLAIMS.md exactly at main.
3. Install pinned dependencies, run noninteractive local setup, regenerate docs/agents.md from production registry and class fixtures and check it. Run documented contract generator write/check for BASE-AGENT-009 and restore generated view files.
4. Run one application build, the touched native audit-target journey, agent guide/site tests and typecheck. No tests or workflows are weakened or skipped. Regenerate sources.lock.json last and check source ownership.
5. Commit one complete candidate with fleet identity and active repository hooks. Inspect every candidate author, committer and trailer. Push the named product branch through cloud-push.py once after touched checks pass; watch exact-SHA Verify with REST within ten GitHub calls and five-minute per-run polling.
6. Save actual non-secret reports and receipts separately, explicitly publish those files to evidence/sx-auth-f42regen-2, and report custody, CI, counts and the unpromoted CLAIM to lane sx. Never land or push main.
