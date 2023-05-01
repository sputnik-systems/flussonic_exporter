FROM golang:1.20-alpine as cacert
RUN apk add -U ca-certificates

FROM scratch
COPY --from=cacert /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY flussonic_exporter /flussonic_exporter
ENTRYPOINT ["/flussonic_exporter"]
