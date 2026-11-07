# Results

The metrics SPEC §14 rule 5 asks for. This run used Claude Code (Opus 5.5) and was measured on 2026-11-06 at commit `d633397`.

## Summary

| Metric | Result |
|---|---|
| Wall-clock time | About 22.5 h elapsed, including idle and overnight time (see below) |
| Token usage / cost | Not visible to the agent. Fill in from the harness (`/cost` or the usage dashboard) |
| Human interventions | 3 ([INTERVENTIONS.md](INTERVENTIONS.md)). 2 before the checklist passed, both "retry" after an interrupted turn |
| §15 checklist | **28 of 30 pass.** The 2 still open both need a real AWS account |
| Tests | **75 Rust tests, all passing** (`cargo test --workspace`). Plus 8 Node tests in `examples/node-app` |
| `cargo clippy --workspace --all-targets -- -D warnings` | Clean |
| Lambda binary size | 10.9 MB (`bootstrap`, arm64, `sam build`). The macOS release build is 9.6 MB |
| Lines of code (`tokei`, code only) | 6,731 Rust, 208 TypeScript, 79 shell, 123 YAML. 7,411 in total, excluding lockfiles, Markdown prose and `SPEC.md` |

## Wall-clock time

- **Start:** 2026-11-05 about 08:21 PST, when the session started, right after the `SPEC.md` commit.
- **§15 automated checks passing:** 2026-11-06 about 07:00 PST, just before the first implementation commits.

The 22.5 h between those times includes long idle stretches: overnight, and waiting for the human after the two interrupted turns. Active working time was much shorter, but the harness doesn't report it to the agent.

## §15 acceptance checklist

| Section | Items | Pass | How it's verified |
|---|---|---|---|
| Auth flow | 10 | 10 | `crates/service/tests/auth_flow.rs` against real MongoDB |
| Tokens | 3 | 3 | `tokens.rs`, and `jose` in `examples/node-app/test/` |
| Invites | 4 | 4 | `invites.rs` |
| Admin | 5 | 5 | `admin.rs`, and the CLI end to end in `crates/cli/tests/e2e.rs` |
| Local dev and ops | 5 | 4 | See below |
| Documentation | 3 | 2 | `docs.rs` and `scripts/run-doc-examples.sh` (20 example blocks) |
| **Total** | **30** | **28** | |

Local dev and ops, and Documentation, in detail:

- **Fresh clone → login works** *(manual)*: **pass, scripted.** A fresh clone from GitHub, run through the README quickstart and then `scripts/smoke.sh`, passes. The smoke script follows the same steps a browser would, with a cookie jar. Nobody has clicked through it in a real browser yet.
- **`sam build` for arm64**: pass.
- **Template guardrails**: pass. `cfn-lint` plus `crates/service/tests/template.rs`.
- **No secrets in the repo or logs**: pass. `repo_hygiene.rs` and `logs.rs`, plus a manual scan of the git history before the repo went public.
- **Deployed to AWS behind a custom domain** *(manual)*: **not done.** Needs the owner's AWS account and domain.
- **Doc examples run**: pass, scripted.
- **`docs/operations.md` is enough to deploy from scratch** *(manual)*: **not done.** Same reason as the AWS deploy.

## Latency

Lambda cold and warm latency **can't be measured until the service is deployed**. These numbers are from a local release build on an Apple Silicon Mac, with MongoDB in Docker on the same machine. They show the code's own cost, not Lambda's.

| Measurement | Result |
|---|---|
| Process start → first `/health` response (a stand-in for cold start, without Lambda's own init) | 30 ms |
| `GET /.well-known/jwks.json`, warm, p95 | 3.2 ms |
| `POST /api/session/refresh`, warm, p95 | 6.3 ms |
| `POST /login`, warm, p95 | 23.9 ms. Most of this is Argon2id hashing, which is deliberately slow |

After deploying, measure with the same endpoints:

- **Cold:** the first request after a fresh deploy, or after about 15 minutes idle. CloudWatch's `REPORT` line gives `Init Duration`.
- **Warm:** p95 over about 50 requests.

Lambda will be slower than the table above: arm64 Graviton at 512 MB, Atlas over the network, and SSM reads on cold start.

## Subjective notes

**Readability and idiomatic Rust**

- The code is split into three crates: `core` (domain logic and the MongoDB store, with no HTTP code), `service` (axum routes) and `cli`. Each route handler is short and hands real work to `core`.
- Errors use `thiserror` in `core` and one `ApiError` type in the service, so every handler returns `Result` and uses `?`.
- Secrets go through `subtle` for constant-time comparisons. Only SHA-256 hashes of session and invite tokens are stored.
- Weak spots:
  - `store.rs` is long, because it holds every collection's queries.
  - `routes/browser.rs` mixes form handling with page rendering. Splitting either would help as features grow.
  - The test harness (`tests/common`) gives every test its own database, which keeps tests isolated. The cost is that `cargo test` needs Docker running.

**Documentation quality**

- **For an auth newcomer:** `docs/how-it-works.md` opens with an "In short" box, defines terms in a glossary, and draws each flow as a Mermaid diagram. A reader new to auth should be able to follow it without outside reading. A docs-review pass cut the jargon and made the docs consistent.
- **Accuracy against the code:** checked by scripts, not by eye. Every runnable doc example runs against the dev setup, the middleware snippet in the integration guide must match `src/auth.ts` exactly, and `docs.rs` checks the required sections and links.
- **Completeness against §12:** every required file exists. Two docs go beyond §12: `docs/migrating-apps.md`, added after the domain mismatch described below, and a log-events table in `docs/operations.md`.
- **Spec gap found:** the spec assumes every app is on a subdomain of one root domain, and the human's real apps aren't. The implementation follows the spec. The mismatch is recorded in [INTERVENTIONS.md](INTERVENTIONS.md), and the two ways forward (move the apps, or add OIDC to the service) are written up in `docs/migrating-apps.md`.

**Decisions:** 38 places where the spec was ambiguous or silent are recorded in [DECISIONS.md](DECISIONS.md). One example is the double-submit CSRF cookie (D11): it's needed because the spec's own `Referrer-Policy: no-referrer` makes browsers send `Origin: null` on same-site form posts.
