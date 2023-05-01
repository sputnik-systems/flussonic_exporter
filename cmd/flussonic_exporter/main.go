package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"text/tabwriter"

	log "github.com/sirupsen/logrus"
)

var (
	version  string
	commitID string
)

var (
	listenAddress       *string
	flussonicAddress    *string
	flussonicConfigPath *string
	insecureSkipVerify  *bool
)

func init() {
	listenAddress = flag.String("listen-address", ":9708", "The address to listen on for HTTP requests.")
	flussonicAddress = flag.String("streamer-api-address", "http://localhost:80", "Flussonic media server api address.")
	flussonicConfigPath = flag.String("streamer-config-path", "/etc/flussonic/flussonic.conf", "Flussonic media server config path.")
	insecureSkipVerify = flag.Bool("insecure-skip-verify", false, "Skip verify cert for Flussonic media server.")
	getVersion := flag.Bool("version", false, "Show exporter version.")
	flag.Parse()

	if *getVersion {
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		if version != "" {
			fmt.Fprintf(w, "version:\t%s\n", version)
		}
		fmt.Fprintf(w, "git commit:\t%s\n", commitID)
		w.Flush()
		os.Exit(0)
	}

	log.SetLevel(log.DebugLevel)
}

func main() {
	http.HandleFunc("/metrics", metricsHandlerFunc)
	http.HandleFunc("/probe", probeHandlerFunc)
	log.Fatal(http.ListenAndServe(*listenAddress, nil))
}
