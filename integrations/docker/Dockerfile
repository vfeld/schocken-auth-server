ARG ALPINEVERSION=3.13
ARG RUSTVERSION=1.50.0

# Dependency Builder for seldom changing objects to utilize docker caching
FROM rust:${RUSTVERSION}-alpine${ALPINEVERSION} as depbuilder
# copy Cargo.lock first to steer docker cache selection
COPY Cargo.lock /usr/src/app/
COPY Cargo.toml /usr/src/app/
COPY build_deps.rs /usr/src/app/
WORKDIR /usr/src/app
RUN apk update \
    && apk add --no-cache build-base jq
RUN cargo build --bin build_deps
RUN cargo test --no-run --bin build_deps

# The application sources
FROM depbuilder as appcommon
COPY src /usr/src/app/src
COPY migrations /usr/src/app/migrations

# App Builder
FROM appcommon as appbuilder
ARG APP=schocken-auth-server
WORKDIR /usr/src/app
RUN cargo build --bin ${APP} && cp /usr/src/app/target/debug/${APP} /tmp/${APP}

# Test Builder
FROM appcommon as testbuilder
ARG APP=schocken-auth-server
ARG APPOBJ=schocken_auth_server
WORKDIR /usr/src/app

RUN TEST_EXE=$(cargo test --no-run --message-format json | jq .executable | grep ${APPOBJ} | sed 's/"//g') && cp $TEST_EXE /tmp/${APP}

# TARGET: Test image
FROM alpine:${ALPINEVERSION} as test
ARG APP=schocken-auth-server
WORKDIR /usr/src/app
COPY --from=testbuilder /tmp/${APP} /usr/local/bin/${APP}
USER 1000
CMD ["${APP}"]

# TARGET: App image (with debug options)
FROM alpine:${ALPINEVERSION} as app
ARG APP=schocken-auth-server
WORKDIR /usr/src/app
COPY --from=appbuilder /tmp/${APP} /usr/local/bin/${APP}
USER 1000
CMD ["${APP}"]

# DEFAULT TARGET
FROM app