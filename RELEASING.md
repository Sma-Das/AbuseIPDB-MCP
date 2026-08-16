# Releasing

Releases are created only from reviewed commits merged to `main`. Never tag an open pull-request branch or an intermediate branch in a stacked change.

## Prepare

1. Merge the complete pull-request stack in dependency order.
2. Pull `main`, confirm the worktree is clean, and verify that the intended release commit is the remote `main` head.
3. Run `make check` and `make test-race` from that exact commit.
4. Replace `Unreleased` in `CHANGELOG.md`, update `CITATION.cff` and `server.json`, and commit those changes through review.

## Publish

Create and push one annotated semantic-version tag from the verified `main` commit:

```bash
git tag -a v1.0.0 -m "AbuseIPDB MCP v1.0.0"
git push origin v1.0.0
```

The `Publish release` workflow validates the tag, repeats the Go tests, publishes native archives through GoReleaser, and publishes the multi-architecture container to Docker Hub and GitHub Container Registry. Stable releases receive full, minor, major, and `latest` container tags. Prerelease tags such as `v1.1.0-rc.1` receive only the full prerelease container tag.

## Verify

1. Confirm all workflow jobs used the intended tag and commit.
2. Verify the GitHub release archives and checksums.
3. Compare the reported container digest with both registries.
4. Run `abuseipdb-mcp -version` from an archive and check `/healthz` against the released container.
5. Confirm stable releases updated `latest`; confirm prereleases did not.

If publication fails, keep the tag immutable, diagnose the failure, and publish a new patch or prerelease version instead of moving or overwriting the tag.
