FROM scratch
COPY flussonic_exporter /flussonic_exporter
ENTRYPOINT ["/flussonic_exporter"]
