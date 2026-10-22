# Releasing

This page describes how a SAS release is versioned, how its notes are
generated, and the steps to cut one. The release for `v1.0.0` is the first to
follow it.

## Versioning

The project follows [Semantic Versioning](https://semver.org/). The root
package and every crate in the Cargo workspace share one version, so a release
tag `vX.Y.Z` always means "every crate is at `X.Y.Z`".

The on-chain `get_version` counters of the contracts are a different thing:
they number WASM upgrade steps (see [UPGRADE_RUNBOOK.md](UPGRADE_RUNBOOK.md))
and do not follow the crate version.

## Release notes

Release notes are generated, not written by hand, by
`scripts/release_notes.sh`. They combine:

1. the `## [X.Y.Z]` section of `CHANGELOG.md`, shown as "Highlights";
2. every non-merge commit since the previous `v*` tag, grouped by
   [Conventional Commit](https://www.conventionalcommits.org/) type;
3. the SHA-256 checksums of the release WASM files.

| Commit type | Section |
|---|---|
| `feat` | Features |
| `fix` | Bug Fixes |
| `perf` | Performance |
| `docs` | Documentation |
| `refactor` | Refactoring |
| `test` | Tests |
| `build`, `ci` | Build and CI |
| `chore`, `style`, `revert` | Maintenance |
| anything else | Other Changes |

A commit with `!` after the type or scope (`feat(registry)!: ...`), or with a
`BREAKING CHANGE:` footer, is listed under Breaking Changes instead of its
type section, with the footer text underneath. `chore(release): ...` commits
are left out. A commit that is not a Conventional Commit is never dropped; it
appears under Other Changes.

Preview the notes for the next release at any time. If the tag does not exist
yet, `HEAD` stands in for it:

```bash
bash scripts/release_notes.sh v1.0.0
bash scripts/release_notes.sh v1.0.0 --previous v0.9.0 --repo Soroban-Eas/soroban-sas
```

`--previous none` includes the whole history, `--checksums <file>` appends a
checksums section, and `--help` lists every option.

## Version checks

`scripts/check_release_version.sh` refuses to continue unless, for the tag
being released:

- the root package and every workspace member declare exactly that version;
- `Cargo.lock` records that version for each of them, so a `--locked` build of
  the tagged commit does not rewrite the lockfile;
- `CHANGELOG.md` has a `## [X.Y.Z]` section.

```bash
bash scripts/check_release_version.sh v1.0.0
```

It lists every problem it finds, not only the first. The release workflow runs
it before building anything.

## Cutting a release

1. Make sure everything for the release is merged to `main` and CI is green.
2. Move the entries under `## [Unreleased]` in `CHANGELOG.md` into a new
   `## [X.Y.Z] - YYYY-MM-DD` section.
3. Set `version = "X.Y.Z"` in the root `Cargo.toml` and in every workspace
   member, then refresh `Cargo.lock` (`cargo update --workspace`). The
   `fuzz/` crate has its own lockfile; refresh it too so the fuzz targets keep
   building with `--locked`.
4. Run the checks and read the notes:

   ```bash
   bash scripts/check_release_version.sh vX.Y.Z
   bash scripts/release_notes.sh vX.Y.Z
   ```

5. Merge that change, then tag the merge commit and push the tag:

   ```bash
   git tag -a vX.Y.Z -m "vX.Y.Z"
   git push origin vX.Y.Z
   ```

6. The `Release` workflow verifies the metadata, builds and optimizes the
   contracts, writes `checksums.sha256`, generates the notes with those
   checksums, and publishes the GitHub release with the WASM files attached.
   A tag with a pre-release suffix (`v1.1.0-rc.1`) is published as a
   pre-release.
7. Copy the checksums into the table at the top of the release's section in
   `CHANGELOG.md` and verify them with `scripts/verify_wasm_hashes.sh`.

## Upgrading a registry that holds schemas

`SchemaRecord` gained an optional `parent_schema_uid` field in 1.0.0. Records
written by earlier builds do not contain it, so a registry that already stores
schemas needs a storage migration before this build is activated. Plan it
with the steps in [UPGRADE_RUNBOOK.md](UPGRADE_RUNBOOK.md).

## Testing the tooling

```bash
bash scripts/test_release_tooling.sh
```

Each case runs in a throwaway git repository or fixture workspace, so it does
not depend on this checkout's history or tags. CI runs it in the "Release
tooling" job of the Developer Tooling workflow.
