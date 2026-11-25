# fips2go exit node. Build from this directory: docker compose build
#
# FIPS_REV is the full commit of the fips pin in shim/Cargo.toml (as
# shim/Cargo.lock records it), so the exit speaks the same fips as the phone.
# Full, because GitHub does not serve a fetch by abbreviated hash. CI checks
# it against the lockfile.
ARG FIPS_REV=a4f4816c036d8e544bd07e1004e9556006ac4270

FROM rust:1.94.1-bookworm AS build
ARG FIPS_REV
RUN apt-get update \
 && apt-get install -y --no-install-recommends clang libclang-dev libnftnl-dev libmnl-dev libdbus-1-dev pkg-config git \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN git init -q fips && cd fips \
 && git fetch -q --depth 1 https://github.com/fr34aky/fips "$FIPS_REV" \
 && git checkout -q FETCH_HEAD
WORKDIR /src/fips
RUN cargo build --release --locked --bin fips --bin fipsctl

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 nftables dnsmasq-base socat python3 libnftnl11 libmnl0 libdbus-1-3 ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/fips/target/release/fips /src/fips/target/release/fipsctl /usr/local/bin/
COPY exitctl.py advert.py entrypoint.sh /opt/exit/
RUN chmod 755 /opt/exit/entrypoint.sh /opt/exit/exitctl.py /opt/exit/advert.py
VOLUME /data
ENTRYPOINT ["/opt/exit/entrypoint.sh"]
