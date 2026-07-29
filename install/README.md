# `install.sh` — Rockfish NDR installer & verifier

The one-command installer for the **Rockfish NDR engine** (the detection engine
this toolkit feeds). This directory holds the **authoritative** copy of the
script; a synced mirror is served at
[`https://docs.rockfishndr.com/install.sh`](https://docs.rockfishndr.com/install.sh)
so the branded one-liner works.

## Install

```bash
curl -fsSL https://docs.rockfishndr.com/install.sh | bash
```

The installer auto-detects the platform:

| Platform | Method |
|---|---|
| Debian / Ubuntu (amd64) | **APT repository** — recommended; enables `apt upgrade` |
| Other Linux / macOS / arm64 | **Docker image** (`rockfishnetworks/toolkit`) |

Prefer to read before you pipe to a shell? Clone the repo and run it directly:

```bash
git clone https://github.com/Fidelis-Machines/rockfish-toolkit.git
./rockfish-toolkit/install/install.sh          # install
./rockfish-toolkit/install/install.sh verify   # diagnostics
./rockfish-toolkit/install/install.sh help      # usage
```

## Verify

`verify` runs **read-only** diagnostics and reports whether the installation is
correct and complete. It writes nothing to disk and **exits non-zero if any
check fails**, so it drops straight into CI or a post-deploy gate:

```bash
curl -fsSL https://docs.rockfishndr.com/install.sh | bash -s -- verify
# or, from a clone:
./install/install.sh verify
```

Checks performed (APT / host install):

- `rockfish` binary present and **runs** (`--version`)
- `libduckdb` resolves for the dynamic linker (the engine's runtime dependency)
- Version-matched DuckDB extensions bundled (`inet`, `httpfs`) for offline `LOAD`
- systemd units registered and enabled (`rockfish`, `rockfish-report`)
- Config directory + `rockfish.yaml` (or the shipped example)
- Data directory (`/var/lib/rockfish`)
- APT signing key + source (so future upgrades work)

For a Docker install it verifies the image is present and `rockfish --version`
runs inside the container. Each line is tagged `[PASS]`, `[WARN]`, or `[FAIL]`;
`WARN` means "not wrong, but worth knowing" (e.g. a service not yet enabled).

## Options

Set via environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `ROCKFISH_METHOD` | auto-detect | Force `apt` or `docker` |
| `ROCKFISH_VERSION` | latest | Pin a version, e.g. `2026.07.6` |
| `ROCKFISH_IMAGE` | `rockfishnetworks/toolkit` | Override the Docker image |
| `ROCKFISH_SERVICES` | prompt | `yes`/`no` — set up the systemd services unattended |
| `ROCKFISH_REPORT_INTERVAL_MIN` | `10` | Report regeneration cadence, in minutes |
| `ROCKFISH_LIBDUCKDB_VERSION` | inferred | Override the libduckdb version installed |

## systemd services

On an APT install the script **asks** whether to enable the two services the
package ships (skip the prompt with `ROCKFISH_SERVICES=yes|no`):

| Service | Role |
|---|---|
| `rockfish.service` | **Detection** — collects Suricata EVE records, enriches them, and stores them as Parquet (`rockfish detect`) |
| `rockfish-report.service` | **Reporting** — regenerates and serves the dashboard **every 10 minutes** (`ROCKFISH_REPORT_INTERVAL_MIN`) |

The report cadence is pinned with a systemd drop-in
(`/etc/systemd/system/rockfish-report.service.d/interval.conf`). The installer
**runs `verify` automatically at the end** so you immediately see whether the
result is complete.

```bash
ROCKFISH_VERSION=2026.07.6 curl -fsSL https://docs.rockfishndr.com/install.sh | bash
ROCKFISH_METHOD=docker      curl -fsSL https://docs.rockfishndr.com/install.sh | bash
```

## What the APT install does

1. Downloads the repo signing key → `/usr/share/keyrings/rockfish-archive-keyring.gpg`
2. Writes the APT source → `/etc/apt/sources.list.d/rockfish.list`
3. `apt-get update` → `apt-get install rockfish`
4. Installs the matching **`libduckdb`** into `/usr/local/lib` (the `.deb`
   doesn't ship it, and the engine links it dynamically) — unless one is already
   present. The version is inferred from the bundled DuckDB extensions, so it
   always matches. On an air-gapped host the download is skipped with
   instructions to install `libduckdb` manually.
5. Creates the parquet storage directory **`/opt/rockfish/data`** and points the
   config's `output.dir` at it (leaves a customized `output.dir` alone).

At the end it reminds you to place the license file at
`/opt/rockfish/etc/rockfish_license.json` and restart the services.

The package installs to `/opt/rockfish` and ships the systemd units, config
examples, and the version-matched DuckDB extensions. Full reference:
[installation docs](https://docs.rockfishndr.com/getting-started/installation.html).

## Maintainers

This is the source of truth. When you change `install.sh`, also update the
served mirror at `ndr/docs/src/install.sh` in the `rockfish` repo and redeploy
the `rockfish_docs` image, so `docs.rockfishndr.com/install.sh` stays in sync.
