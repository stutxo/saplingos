# Contributor tools

`prechecks.sh` implements the Rust whitespace checks used by `just prechecks`:

- `rust_no_spaces_for_indent`: require tabs rather than spaces for indentation.
- `rust_no_whitespace_on_empty_lines`: reject whitespace-only lines.

The checks cover `sdk/`, `protocol/`, `rpc/`, and `testing/`. Generated files
marked through Git attributes are excluded.

Agent guidance, historical review notes, and research live under `agents/`.
Old upstream GitLab CI downloads and release instructions in that history are
not Sapling's build workflow. Use [BUILDING.md](../BUILDING.md) and the
[GitHub SDK workflow](../.github/workflows/sdk.yml) for current commands.

This repository no longer contains server-release, CLI-release, or deployment
tooling. Those components are maintained in upstream Bark.
