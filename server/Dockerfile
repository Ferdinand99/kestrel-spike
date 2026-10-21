# Fully static musl build of the spike server, including symbolic-demangle's C++ Swift demangler.
FROM rust:1.99.1-alpine3.24 AS build
# build-base brings g++ and the static libstdc++.a/libgcc.a the Swift demangler links against.
RUN apk add --no-cache build-base file
WORKDIR /src
# The musl target links statically by default (crt-static). Setting
# RUSTFLAGS=-C target-feature=+crt-static without an explicit --target breaks proc-macro
# crates on musl hosts, so we rely on the default and verify the result below.
ENV CARGO_BUILD_JOBS=4
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked \
 && cp target/release/kestrel-spike /kestrel-spike \
 && file /kestrel-spike \
 && ! (ldd /kestrel-spike 2>&1 | grep -q '=>') \
 && /kestrel-spike --version

FROM scratch
COPY --from=build /kestrel-spike /kestrel-spike
ENV BIND_ADDR=0.0.0.0:9000 \
    CAPTURE_DIR=/data/captures \
    DATA_DIR=/data/store
EXPOSE 9000
ENTRYPOINT ["/kestrel-spike"]
