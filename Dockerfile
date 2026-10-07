# Multi-stage build producing a tiny static binary on a distroless base.
FROM golang:1.26-alpine@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c AS build
WORKDIR /src

# Cache modules first.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# CGO disabled → fully static binary (modernc.org/sqlite is pure Go, so this works).
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/relay ./cmd/relay
# Pre-create the data dir so a freshly-created named volume inherits nonroot ownership
# (Docker seeds a new empty volume from the image path's contents + permissions). Without
# this the volume defaults to root-owned and the nonroot process can't write the key store.
RUN mkdir -p /data && touch /data/.keep

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
WORKDIR /app
COPY --from=build /out/relay /app/relay
COPY --from=build --chown=65532:65532 /data /data
# The SQLite key store lives on a mounted volume.
VOLUME ["/data"]
ENV RELAY_DB_PATH=/data/relay.db
EXPOSE 8090
USER nonroot:nonroot
ENTRYPOINT ["/app/relay"]
