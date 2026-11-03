FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/fingerprints ./cmd/fingerprints

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/fingerprints /fingerprints
VOLUME /data
EXPOSE 8443 8080
ENTRYPOINT ["/fingerprints", "-db", "/data/fingerprints.db"]
