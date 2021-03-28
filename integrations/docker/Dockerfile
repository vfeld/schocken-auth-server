# Build dependencies
FROM rust:1.50.0-alpine3.13 as depbuilder
ARG APP=schocken-auth-server

WORKDIR /usr/src/app
RUN apk update \
    && apk add --no-cache build-base
COPY build_deps.rs .
COPY Cargo.toml .
COPY Cargo.lock .
RUN cargo build --release --bin build_deps

# Build app
FROM depbuilder as appbuilder
ARG APP=schocken-auth-server
COPY src src
COPY migrations migrations
RUN cargo build --release --bin ${APP}  

# Runtime image
FROM alpine:3.13
ARG APP=schocken-auth-server
WORKDIR /usr/src/app

RUN apk update \
    && apk add --no-cache ca-certificates tzdata \
    && rm -rf /var/cache/apk/*
COPY --from=appbuilder /usr/src/app/target/release/${APP} /usr/local/bin/${APP}

USER 1000

CMD ["${APP}"]
