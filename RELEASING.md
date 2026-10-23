# Releasing InjectKit

Publishing is **always a manual decision of the maintainer**. The release workflow
(`.github/workflows/release.yml`) is prepared but nothing triggers it until a GitHub release
is published. No agent or CI job creates tags, releases, pushes or changes repository
visibility.

## Who does what

| Step | Owner |
|---|---|
| Quality gate, packaging checks, changelog, version bump | Contributor / agent (this checklist) |
| Choosing the release, tagging, creating and publishing the GitHub release | **Maintainer** |
| Creating the PyPI project / pending publisher and the protected `pypi` environment | **Maintainer** |
| Deciding repository visibility and the security contact | **Maintainer** |

## One-time setup (maintainer)

1. **Check that the name `injectkit` is free on PyPI** (it was never verified; if it is taken,
   change `name` in `pyproject.toml`, the entry points and the docs before going further).
2. In the GitHub repository, create an environment named **`pypi`** and protect it
   (required reviewers, restrict to the release branch/tags). The publish job waits for it.
3. On PyPI, add a **trusted publisher** (pending publisher for a new project) pointing at this
   repository, workflow file `release.yml` and environment `pypi`. No API token is created or
   stored; the workflow uses OpenID Connect (`id-token: write` on the publish job only).
4. Check that no `TODO-USER` placeholder is left (`git grep -n "TODO-USER"`). Security contact,
   author and project URLs are filled in. Check on pypi.org that the name `injectkit` is free.
5. Enable GitHub Code Scanning if you want the SARIF upload job (`injectkit-selftest`) to
   succeed; it is advisory and does not block merges.

## Pre-release checklist (before every release)

The Definition of Done (`Planning_files/DefinitionOfDone.md`, "Phase 5 / release") is the
authority; these are the commands. Run them from a clean checkout of the commit to release.

- [ ] `uv sync --locked --all-extras`
- [ ] `uv run ruff format --check .` and `uv run ruff check .`
- [ ] `uv run mypy`
- [ ] `uv run pytest --cov` (coverage >= 85%, no skipped test without a written reason)
- [ ] `uv export --locked --all-extras --no-emit-project -o req.txt && uv run pip-audit -r req.txt --disable-pip --require-hashes` finds nothing
- [ ] `gitleaks detect --source . --no-banner --redact` (full history) finds nothing
- [ ] `uv build`, then inspect: `uv run python -m zipfile -l dist/*.whl` contains
      `injectkit/py.typed` and the payload YAML files and no `.claude`, tests or planning files
- [ ] Clean-venv smoke: `uv run --isolated --no-project --with dist/<wheel> injectkit version`,
      `... injectkit validate examples/target.example.yaml`,
      `... injectkit run examples/target.example.yaml --suite basic --dry-run`
      (export dummy values for the env vars the example config names)
- [ ] `CHANGELOG.md` has an entry for the version and `version` in `pyproject.toml` is set
      (the package reads its version from there; the tag must be `v<version>`)
- [ ] `README.md`, `docs/` and `SECURITY.md` match the behavior of this version
- [ ] No open CRITICAL/HIGH finding from the security review; residual risks are listed in
      `docs/authorization.md` and `SECURITY.md`
- [ ] `git grep -n "TODO-USER"` lists only placeholders you have decided to accept

## Publishing (maintainer)

1. Merge the release branch into the default branch (your decision) and push.
2. Create the tag `v<version>` and a GitHub release for it, then **publish** the release.
3. The workflow builds from that tag, re-runs the quality gate, refuses to continue if the tag
   differs from the package version, and hands the artifacts to the `pypi` environment.
4. Approve the environment deployment. Verify the project page on PyPI and install the
   published version in a fresh virtual environment.

## Rolling back

PyPI files cannot be replaced. If a release is broken, **yank** it on PyPI (it stays
resolvable for pinned users), fix forward and publish a new patch version.
