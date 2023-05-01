package main

import (
	"bufio"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"

	"github.com/sputnik-systems/flussonic_exporter/pkg/sdk"
	"github.com/sputnik-systems/flussonic_exporter/pkg/sdk/storage"
)

var (
	localStreamStatus          *prometheus.GaugeVec
	localStreamerUptime        prometheus.Gauge
	localStreamerTotalClients  prometheus.Gauge
	localStreamerTotalStreams  prometheus.Gauge
	localStreamerOnlineStreams prometheus.Gauge
)

func init() {
	localStreamStatus := StreamStatusCollector()
	localStreamerUptime := StreamerUptimeCollector()
	localStreamerTotalClients := StreamerTotalClientsCollector()
	localStreamerTotalStreams := StreamerTotalStreamsCollector()
	localStreamerOnlineStreams := StreamerOnlineStreamsCollector()
	prometheus.MustRegister(
		localStreamStatus,
		localStreamerUptime,
		localStreamerTotalClients,
		localStreamerTotalStreams,
		localStreamerOnlineStreams,
	)
}

var (
	targets = map[string]*sdk.Client{}
)

func metricsHandlerFunc(w http.ResponseWriter, r *http.Request) {
	username, password, err := getAuthInfo()
	if err != nil {
		log.Errorf("failed to get local auth info: %s", err)
	}

	streamer, ok := targets["local"]
	if !ok {
		opts := []sdk.ClientOption{
			sdk.WithBasicAuth(username, password),
		}
		if *insecureSkipVerify {
			opts = append(opts, sdk.WithInsecureSkipVerify())
		}
		streamer = sdk.NewStreamerClient(*flussonicAddress, opts...)
		targets["local"] = streamer
	}

	// collect streamer metrics
	log.Debug("collecting streamer info")
	configStats, err := streamer.GetConfigStats()
	if err != nil {
		log.Error(err)
	}
	localStreamerUptime.Set(float64(configStats.GetUptime()))
	localStreamerTotalClients.Set(float64(configStats.GetTotalClients()))
	localStreamerTotalStreams.Set(float64(configStats.GetTotalStreams()))
	localStreamerOnlineStreams.Set(float64(configStats.GetOnlineStreams()))

	// collect streams metrics
	streams := make([]storage.Stream, 0)
	for cursor := ""; ; {
		log.Debugf("collecting streams info, cursor: %s", cursor)
		page, err := streamer.GetStreams(cursor)
		if err != nil {
			log.Error(err)
		}

		streams = append(streams, page.ListStreams()...)
		cursor = page.GetNext()

		if cursor == "" {
			break
		}
	}
	prometheus.Unregister(localStreamStatus)
	prometheus.MustRegister(localStreamStatus)
	for _, value := range streams {
		s := localStreamStatus.With(prometheus.Labels{
			"name":           value.GetName(),
			"title":          value.GetTitle(),
			"dvr_expiration": strconv.FormatUint(value.GetDvr().GetExpiration(), 10),
		})

		if value.GetStats().GetAlive() {
			s.Set(1)
		} else {
			s.Set(0)
		}
	}

	h := promhttp.Handler()
	h.ServeHTTP(w, r)
}

func probeHandlerFunc(w http.ResponseWriter, r *http.Request) {
	remoteStreamStatus := StreamStatusCollector()
	remoteStreamerUptime := StreamerUptimeCollector()
	remoteStreamerTotalClients := StreamerTotalClientsCollector()
	remoteStreamerTotalStreams := StreamerTotalStreamsCollector()
	remoteStreamerOnlineStreams := StreamerOnlineStreamsCollector()

	registry := prometheus.NewRegistry()
	registry.MustRegister(
		remoteStreamStatus,
		remoteStreamerUptime,
		remoteStreamerTotalClients,
		remoteStreamerTotalStreams,
		remoteStreamerOnlineStreams,
	)

	target := r.URL.Query().Get("target")
	username := r.URL.Query().Get("username")
	password := r.URL.Query().Get("password")
	streamer, ok := targets[target]
	if !ok {
		opts := []sdk.ClientOption{
			sdk.WithBasicAuth(username, password),
		}
		if *insecureSkipVerify {
			opts = append(opts, sdk.WithInsecureSkipVerify())
		}
		streamer = sdk.NewStreamerClient(target, opts...)
		targets[target] = streamer
	}

	// collect streamer metrics
	log.Debug("collecting remote streamer info")
	configStats, err := streamer.GetConfigStats()
	if err != nil {
		log.Error(err)
	}
	remoteStreamerUptime.Set(float64(configStats.GetUptime()))
	remoteStreamerTotalClients.Set(float64(configStats.GetTotalClients()))
	remoteStreamerTotalStreams.Set(float64(configStats.GetTotalStreams()))
	remoteStreamerOnlineStreams.Set(float64(configStats.GetOnlineStreams()))

	// collect streams metrics
	streams := make([]storage.Stream, 0)
	for cursor := ""; ; {
		log.Debugf("collecting remote streamer streams info, cursor: %s", cursor)
		page, err := streamer.GetStreams(cursor)
		if err != nil {
			log.Error(err)
		}

		streams = append(streams, page.ListStreams()...)
		cursor = page.GetNext()

		if cursor == "" {
			break
		}
	}
	for _, value := range streams {
		s := remoteStreamStatus.With(prometheus.Labels{
			"name":           value.GetName(),
			"title":          value.GetTitle(),
			"dvr_expiration": strconv.FormatUint(value.GetDvr().GetExpiration(), 10),
		})

		if value.GetStats().GetAlive() {
			s.Set(1)
		} else {
			s.Set(0)
		}
	}

	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
}

func getAuthInfo() (string, string, error) {
	c, err := os.Open(*flussonicConfigPath)
	if err != nil {
		return "", "", fmt.Errorf("media server config file open failed: %s", err)
	}
	defer c.Close()

	reAuthLine := regexp.MustCompile(`(?:^edit_auth\s|\s|;$)`)
	reAuthLineExists := regexp.MustCompile(`^edit_auth`)

	scanner := bufio.NewScanner(c)
	for scanner.Scan() {
		line := scanner.Text()

		if reAuthLineExists.MatchString(line) {
			reAuth := reAuthLine.Split(line, -1)

			return reAuth[1], reAuth[2], nil
		}
	}

	return "", "", errors.New("auth info doesn't found in configuration file")
}
