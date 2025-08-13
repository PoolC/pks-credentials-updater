# Build stage
FROM golang:1.24.3-bookworm AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY main.go logger.go ./

RUN CGO_ENABLED=0 go build -o credentials-updater .

FROM gcr.io/distroless/base-debian12

COPY --from=builder /app/credentials-updater /credentials-updater

# Run as non-root user
USER 65534:65534

ENTRYPOINT ["/credentials-updater"]
