# In-app updates

VulnS can update itself with one click. When a newer, compatible release is published,
the dashboard shows an **Update now** button. Clicking it backs up the database,
downloads the new image, swaps the container and verifies the result; a failure at any
point after the swap restores the previous container and the backup automatically.

## How it fits together

```
vulns (the app)                    vulns-updater (the sidecar)
  GET  /api/version                  holds the Docker socket
  GET  /api/update/status  ──────►   GET  /status
  POST /api/update/run     ──────►   POST /update   {image, version}
  POST /api/update/backup  ◄──────   (called first, returns a verified snapshot)
  GET  /health/deep        ◄──────   (called after the swap, gates the update)
```

- **Version detection.** Every release carries a `release.json` manifest (see below).
  The app fetches `releases/latest/download/release.json` from GitHub at most once per
  six hours, server-side, with a 3-second timeout. A failure simply hides the banner.
  `VULNS_UPDATE_CHECK=false` disables the check entirely.
- **Compatibility gate.** The button appears only when the published version is strictly
  newer *and* `min_updatable_from` / `min_schema` in the manifest say the running build
  can upgrade to it. A dev build never shows an update.
- **Execution.** Only the sidecar touches Docker. It listens on the compose network,
  never on a published port, and requires `VULNS_UPDATER_TOKEN` on every call. It only
  pulls images under the `ghcr.io/gnutlam/vulns:` prefix.

## What an in-app update replaces

Only the app container. The new container keeps the old one's volumes, ports, labels and
the environment set in compose, but not the environment its old image defined: the new
image brings its own (`VULNS_APP_VERSION` among it). The release version is also written
into the image as `app/BUILD_VERSION`, which the app reads first, so a container can never
report an older version than the code it runs.

The updater sidecar is not replaced by an in-app update. To update it as well, and to
bring Compose back in line with the running release:

```bash
docker compose pull
docker compose up -d --force-recreate
```

## Database safety

The image swap cannot touch your data: everything lives in the `vulns_data` volume
(`/data`), which is mounted into both the old and the new container. Schema changes are
applied in place by ordered, run-once migrations recorded in `schema_migrations`; a
pre-update snapshot is taken with SQLite's `VACUUM INTO` (consistent, compact, taken
while the app keeps serving) and verified with `PRAGMA integrity_check` **before**
anything is swapped. No verified backup means no update.

The updater's verify step calls `/health/deep`, which re-checks integrity, foreign keys
and the schema stamp. If it fails, the previous container is renamed back, the newest
backup is copied over `vulns.db` (safe: the new app has served no writes yet), and the
old version is verified again. Because the session secret lives in the data volume, you
stay signed in across updates.

Artifacts under `/data/backups/`:

| File | Content |
| --- | --- |
| `backup-<timestamp>.db` | pre-update snapshots; the 5 newest are kept |
| `update-state.json` | the live state of the last update operation |
| `update-log.jsonl` | one JSON line per event, the debugging record for any update |

## Release checklist

1. Merge to `main`; CI (`.github/workflows/ci.yml`) runs ruff.
2. Tag `vX.Y.Z` and push. The release workflow lints again, builds the app and updater
   images for amd64 and arm64, pushes them to ghcr.io and publishes a GitHub Release
   with `release.json` attached. Bump `min_updatable_from` / `min_schema` in the
   workflow when a release cannot upgrade from very old versions.
3. Try the update on a scratch deployment first (a copy of the compose stack with a
   clone of the data volume), then click **Update now** in production.

`release.json` schema:

```json
{
  "version": "1.2.0",
  "image": "ghcr.io/gnutlam/vulns:1.2.0",
  "min_updatable_from": "0.1.0",
  "min_schema": 1,
  "notes_url": "https://github.com/GnuTLam/vulns/releases/tag/v1.2.0"
}
```

## Manual rollback

If an update ever leaves the stack in a bad state (including a failed automatic
rollback):

```bash
docker compose down
cp <backup file>  <into the volume>   # docker run --rm -v vulns_vulns_data:/data alpine sh -c \
                                      #   "cp /host-backup.db /data/vulns.db"
VULNS_VERSION=<previous version> docker compose up -d
```

The backup files are plain SQLite databases; copy the newest one over `vulns.db` while
the app container is stopped.

## Security model

The sidecar is as powerful as root on the host (it holds the Docker socket), so it is
deliberately minimal: it exposes three endpoints, requires the shared token, pulls only
from the fixed image prefix, publishes no ports, and runs with `no-new-privileges`. The
app container gains no new mounts or capabilities — its only new power is an HTTP call
to the sidecar. The update check is a fetch from GitHub; no data leaves the host.
