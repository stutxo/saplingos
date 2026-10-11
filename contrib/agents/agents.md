## Before You Start

**Check the nix flake is loaded before writing any code.**

Run `printenv IN_NIX_SHELL`. If the flake isn't loaded, remind the user:

> "Please restart in a shell with the nix flake loaded (`nix develop` or direnv)."

Do not write code until the environment is confirmed.

## Skills

Use the skills in `contrib/agents/skills/` extensively:

| Skill | When to use |
|-------|-------------|
| `running-and-debugging-tests.md` | Running tests and investigating failures |
| `writing-tests.md` | Test patterns and conventions |
| `review.md` | Reviewing branches (with or without fix-ups) |
| `protocol-encoding.md` | Working with ProtocolEncoding (backward compat, no panics, DoS protection) |
| `documentation.md` | Documentation conventions (vocabulary is in CONTRIBUTING/style_guide.md) |
| `database-schema.md` | Finding the full database DDL (use schema.sql, not migrations) |
| `prompts.md` | Managing prompts and research |
| `corrections.md` | When corrected, encode the fix into skill files |

## Testing

**Never run integration tests with `cargo test` directly.** They require environment variables set by `just`.

```bash
just checks      # Pre-commit: style checks + cargo check
just unit        # Unit tests
just unit <name> # Specific unit test
just int         # Integration tests (bitcoind backend)
just int <name>  # Specific integration test
```

The default shell and checks cover only the client SDK and protocol/RPC libraries.
Integration fixtures are external and opt-in; see `BUILDING.md`. Historical
changelog and GitLab CI skills describe upstream workflows, not this extraction.

## Code Style

Primary goal: **code that humans can understand**.
Correct but hard-to-understand code is worse than clear code with a bug (bugs get caught in review).

- **Tabs** for indentation
- **No strict rustfmt** - format for readability
- **No blind clippy fixes** - they can introduce bugs
- Follow bitcoin patterns and naming conventions
- Imports should be at the top of a module. Don't put imports inside a function.
- Look at surrounding code to match style

See `CONTRIBUTING/STYLE.md` for details on imports, serialization, etc.

## Writing Style and Vocabulary

Follow `CONTRIBUTING/style_guide.md` for vocabulary and writing style.
That guide applies to all text: documentation, comments, docstrings,
changelogs, commit messages, and user-facing strings.

## Commit Hygiene

- Prefix with subsystem: `sdk:`, `protocol:`, `rpc:`, `ci:`, `testing:`
- Focus on **why**, not what - help reviewers understand context
- Small, logical commits that individually compile (`just check`)
- Squash fixups into original commits (reviewers use `git range-diff`)

## Error Handling

- `ark-lib`: Use `thiserror` - errors are part of the API
- `sapling-sdk`: Use `anyhow` - propagate errors to the application
- Use `thiserror` elsewhere when you need to handle errors differently
- Avoid creating too many error types - be pragmatic

## Database

Use `sdk/schema.sql` for the wallet's complete SQLite DDL. Database migrations
must preserve program descriptors, saved recoveries, and restart safety.
Server PostgreSQL schema and migrations belong to the pinned upstream fixtures.
