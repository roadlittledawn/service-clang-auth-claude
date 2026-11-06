# Human interventions

Per SPEC §14 rule 3: each time the human had to step in beyond routine tool permissions.

| When (PST) | What happened | Why |
|---|---|---|
| 2026-11-05, during service route implementation | The human typed **"retry"** after an assistant turn ended before writing the browser route handlers. | The turn was interrupted; no correction of direction or content. Work resumed exactly where it stopped. |
| 2026-11-06, during documentation | The human typed **"try again"** after an assistant turn ended before writing `docs/how-it-works.md`. | Same as above: an interrupted turn, no change of direction. |
| 2026-11-06, after the §15 automated checks passed | The human pointed out that their apps run on **different domains**, not subdomains of one root domain, and asked how that affects the design. | A requirements mismatch: SPEC §1 lists "apps outside `{ROOT_DOMAIN}`" as a non-goal, so the implementation follows the spec but not the real use case. The agent paused to explain the impact before changing anything. |

Not counted as interventions (recorded for completeness):
- Installing the toolchain (rustup, cargo-lambda, SAM CLI, cfn-lint, tokei via Homebrew) and starting Docker Desktop. The agent did these itself.
- Port 4000 is also used by an unrelated local Node process (on IPv4 `*:4000`). The agent worked around it with no human action: the service binds `127.0.0.1` and `::1` explicitly (DECISIONS D10).
