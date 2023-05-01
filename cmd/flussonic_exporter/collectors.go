package main

import (
	"github.com/prometheus/client_golang/prometheus"
)

func StreamStatusCollector() *prometheus.GaugeVec {
	return prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "flussonic_stream_status",
			Help: "flussonic streams status.",
		},
		[]string{"name", "title", "dvr_expiration"},
	)
}

func StreamerUptimeCollector() prometheus.Gauge {
	return prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "flussonic_server_uptime",
			Help: "streamer uptime.",
		},
	)
}

func StreamerTotalClientsCollector() prometheus.Gauge {
	return prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "flussonic_server_total_clients",
			Help: "total streamer clients.",
		},
	)
}

func StreamerTotalStreamsCollector() prometheus.Gauge {
	return prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "flussonic_server_total_streams",
			Help: "total streams count.",
		},
	)
}

func StreamerOnlineStreamsCollector() prometheus.Gauge {
	return prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "flussonic_server_online_streams",
			Help: "online streams count.",
		},
	)
}
