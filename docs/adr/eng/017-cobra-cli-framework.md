# ADR 017: Cobra as the CLI framework for dpki-cli

## Status
Accepted

## Context
Until Phase 5 `dpki-cli` had two helper commands (`challenge`,
`challenge-check`) dispatched by hand over the standard `flag` package, the
same pattern `dpkid` uses. Phase 5 grows it into the full client: ten commands,
shared global flags (`--node`, `--chain-id`, `--config`, `-v`), required-flag
validation, subcommand grouping (`keys generate`/`keys show`) and shell
completion. Hand-rolled dispatch scales poorly past a couple of commands:
every command re-parses global flags, help text is maintained by hand, and
there is no uniform error path.

## Decision
`dpki-cli` is built on `github.com/spf13/cobra`, the de-facto standard of the
Go ecosystem (kubectl, docker, cometbft, cosmos-sdk). Conventions:

- `commands.NewRootCommand()` builds a **fresh, self-contained command tree**;
  nothing is package-global. Tests run whole commands in-process with their own
  stdin/stdout buffers.
- Global flags live on the root as persistent flags and are resolved against
  the optional config file in `PersistentPreRunE` (flag > config > default).
- Commands contain no business logic: they parse flags, call
  `internal/types`/`internal/crypto` and the `client` package, and format
  output. Validation verdicts belong to the node.

`dpkid` stays on the standard `flag` package: two subcommands do not justify
the dependency, and the operator-facing daemon has different UX needs.

## Consequences
- **Positive:** `--help` for every command, required-flag enforcement and
  `completion bash|zsh|fish` come for free.
- **Positive:** fresh command trees make CLI tests trivial and parallel-safe.
- **Negative:** a new direct dependency (cobra was already an indirect one via
  CometBFT).
- **Negative:** two CLI styles coexist in `cmd/` (flag-based `dpkid`,
  cobra-based `dpki-cli`). Accepted: the daemon's interface is two fixed
  subcommands, while the client's interface is the product.
