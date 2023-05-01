FROM golang:1.20 as build

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download -x

COPY ./ ./
ENV CGO_ENABLED=0
RUN go build -o ./flussonic_exporter ./cmd/flussonic_exporter


FROM scratch

COPY --from=build /app/flussonic_exporter /flussonic_exporter

ENTRYPOINT ["/flussonic_exporter"]
