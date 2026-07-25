# Run Rockfish in Docker

This [`Dockerfile`](Dockerfile) builds a container that runs the `rockfish` CLI
(the Rockfish NDR sensor/processor — ingest Suricata EVE → Parquet, hunt,
report, MCP, …) by installing the published `.deb` from the Rockfish APT
repository. The image always tracks an official release; nothing is built from
source.

## Build

```bash
cd docker

# Latest published release
docker build -t rockfish .

# Pin a specific version
docker build --build-arg ROCKFISH_VERSION=2606.a -t rockfish:2606.a .
```

## Run

```bash
# Show version / help
docker run --rm rockfish --version
docker run --rm rockfish --help

# Ingest a Suricata EVE socket into Parquet (mount your data + config)
docker run --rm \
  -v /var/run/suricata:/var/run/suricata \
  -v /var/lib/rockfish:/var/lib/rockfish \
  -v /opt/rockfish/etc:/opt/rockfish/etc \
  rockfish ingest --socket /var/run/suricata/eve.sock
```

`ENTRYPOINT` is `rockfish`, so anything after the image name is passed straight
to the CLI. Ports `3000` (HTTP report server) and `8082` (MCP) are exposed —
publish them with `-p` when you run those subcommands.

## Build args

| Arg | Default | Purpose |
|-----|---------|---------|
| `ROCKFISH_APT` | `https://repo.rockfishndr.com` | APT repo base URL to install from |
| `ROCKFISH_VERSION` | *(empty)* | Empty = latest published; set to pin (e.g. `2606.a`) |
| `DUCKDB_VERSION` | `v1.2.2` | `libduckdb` version (must match the release) |

## What's in the image

- `/opt/rockfish/bin/rockfish` — the CLI (on `PATH`)
- `/opt/rockfish/etc/` — example config (`rockfish.yaml`, `rockfish.env`)
- `/opt/rockfish/LICENSE` — the Rockfish NDR EULA (the software is licensed, not
  sold; use is governed by <https://rockfishndr.com/terms>)
- `/usr/share/doc/rockfish/THIRD-PARTY-NOTICES.yaml` — bundled OSS notices

## Notes

- The repo is GPG-signed; the build fetches the signing key
  (`rockfish-archive-keyring.gpg`) and installs with `signed-by`, so a tampered
  mirror fails `apt-get update`.
- **arm64:** change `arch=amd64` in the Dockerfile's `deb` line to `arm64`, use
  the arm64 `libduckdb` asset, and build a matching arm64 `.deb`.
- Without a license file the CLI runs at the Free tier; mount a license to
  unlock a higher tier (see <https://rockfishndr.com>).
