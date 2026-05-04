# Contributing

We happily accept both issues and pull requests for bug reports, bug fixes, feature requests, feature implementations, and documentation improvements.

For new features we recommend that you create an issue first so the feature can be discussed and to prevent unnecessary work in case it is not a feature we want to support. We also realize that sometimes code needs to be in place to allow a meaningful discussion, so creating an issue upfront is not a requirement.

## Building and testing

Prerequisites:

- [uv](https://docs.astral.sh/uv/)
- Python 3.10 or newer (see `requires-python` in [`pyproject.toml`](pyproject.toml))

From the repository root:

```bash
uv sync
uv run python -c "import nordstellar_remote_mcp_proxy"
```

To run the proxy for real, pass a remote MCP URL (or set `NORDSTELLAR_REMOTE_MCP_URL`); see [`README.md`](README.md).

There is no separate test suite in this repository yet; CI runs [MCPB](https://github.com/anthropics/mcpb) validate/pack on pushes and pull requests (see [`.github/workflows/validate-mcpb.yml`](.github/workflows/validate-mcpb.yml)). Ensure changes still pass that workflow.

## PR workflow

We want to get your changes merged as fast as possible, and we know you want that too. To help with this there are a few things you can do to speed up the process:

### Build and validate locally

The local feedback cycle is faster than waiting for CI. Make sure `uv sync` succeeds and the module imports. If you change the MCPB bundle, run the same validate/pack steps as in CI when possible.

A green CI is a happy CI.

### PR hygiene

On top of CI being green, every PR will go through code review, and you can help us speed up the review process by making your PR easier to review. Here are some guidelines:

**Small PRs are easier to review than big PRs**, so try to keep your PRs small and focused. To achieve that, try to make sure your PR does not contain multiple unrelated changes and if you are doing bigger feature work, try to split the work into multiple smaller PRs that solve the problem together.

**A clean history can make things easier.** Some PRs are easier to review commit-by-commit, rather than looking at the full changelist in one go. To enable that, prefer `rebase` over `merge` when updating your branch. Keeping PRs small and short-lived will also help keep your history clean since there is less time for upstream to change that much.

## Licensing

This project is released under the GNU General Public License v3.0 only. For more details please refer to the [`LICENSE`](LICENSE) file.

## Developer Certificate of Origin

We use the [Developer Certificate of Origin](https://developercertificate.org/) (DCO) to certify that you have the right to submit your contribution under the project license.

Every commit must include a `Signed-off-by` line with your name and email, matching your git author. Use:

```bash
git commit -s
```

That adds a sign-off like:

```text
Signed-off-by: Random J Developer <random@developer.example.org>
```

By adding that line, you certify the [DCO 1.1](https://developercertificate.org/) attestation. If you need help with sign-off or rebasing, ask in the PR and we will guide you.

## Code of conduct

Nord Security projects follow the Contributor Covenant. When participating here, you are expected to honor the [Code of Conduct](CODE_OF_CONDUCT.md).

**Thank you!**
