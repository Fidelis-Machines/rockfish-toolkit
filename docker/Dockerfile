# Rockfish NDR — run the rockfish CLI in a container.
#
# Installs the published rockfish .deb from the Rockfish APT repository, so the
# image always tracks an official release (no source build required).
# See ./README.md for build/run instructions.
#
#   docker build -t rockfish .
#   docker build --build-arg ROCKFISH_VERSION=2606.a -t rockfish:2606.a .
FROM debian:bookworm-slim

# Overridable at build time.
ARG ROCKFISH_APT=https://repo.rockfishndr.com
# Empty = install the latest published release; set to pin (e.g. 2606.a).
ARG ROCKFISH_VERSION=
ARG DUCKDB_VERSION=v1.2.2

# Runtime deps the .deb declares (libssl3; libsasl2 for the kafka feature) plus
# tooling to add the repo and fetch libduckdb (not an apt package).
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg wget unzip libssl3 libsasl2-2 \
    && rm -rf /var/lib/apt/lists/*

# libduckdb shared library — must match the version the binary was built against.
RUN wget -q "https://github.com/duckdb/duckdb/releases/download/${DUCKDB_VERSION}/libduckdb-linux-amd64.zip" \
    && unzip -q libduckdb-linux-amd64.zip -d /usr/local/lib/ \
    && ldconfig \
    && rm -f libduckdb-linux-amd64.zip

# Add the signed Rockfish APT repo and install the CLI from the published .deb.
RUN install -d /usr/share/keyrings \
    && curl -fsSLo /usr/share/keyrings/rockfish-archive-keyring.gpg \
         "${ROCKFISH_APT}/rockfish-archive-keyring.gpg" \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/rockfish-archive-keyring.gpg] ${ROCKFISH_APT} stable main" \
         > /etc/apt/sources.list.d/rockfish.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends "rockfish${ROCKFISH_VERSION:+=$ROCKFISH_VERSION}" \
    && apt-get purge -y curl gnupg wget unzip && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/opt/rockfish/bin:${PATH}"

# HTTP report server (3000) and MCP server (8082); adjust to your config.
EXPOSE 3000 8082

ENTRYPOINT ["rockfish"]
CMD ["--help"]
