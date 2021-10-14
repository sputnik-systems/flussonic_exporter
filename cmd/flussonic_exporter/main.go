package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"text/tabwriter"

	log "github.com/sirupsen/logrus"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Meta struct {
	Flags   Flags
	Metrics Metrics
	Config  Config
}

type Config struct {
	BasicAuth BasicAuth
	Client    *http.Client
}

type BasicAuth struct {
	Username string
	Password string
}

type Flags struct {
	Addr                *string
	Backend             *string
	InsecureSkipVerify  *bool
	Config              *string
	Version             *bool
	StreamsRequestLimit *uint64
}

type Metrics struct {
	FlussonicStreams
	FlussonicServer
}

type FlussonicStreams struct {
	Streams []FlussonicStream
}

type FlussonicStream struct {
	Name, Title string
	Dvr         FlussonicStreamDvr
	Stats       FlussonicStreamStats
}

type FlussonicStreamStats struct {
	AgentStatus string
	Alive       bool
	RetryCount  uint64
}

type FlussonicStreamDvr struct {
	Expiration uint64
}

type FlussonicServer struct {
	Uptime        uint64
	TotalClients  uint64 `json:"total_clients"`
	TotalStreams  uint16 `json:"total_streams"`
	OnlineStreams uint16 `json:"online_streams"`
}

func probeHandler(w http.ResponseWriter, r *http.Request) {
	streamStatus := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "flussonic_stream_status",
			Help: "flussonic streams status.",
		},
		[]string{"name", "title", "dvr_expiration"},
	)
	mediaServerUptime := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "flussonic_server_uptime",
			Help: "streamer uptime.",
		},
	)
	mediaServerTotalClients := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "flussonic_server_total_clients",
			Help: "total streamer clients.",
		},
	)
	mediaServerTotalStreams := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "flussonic_server_total_streams",
			Help: "total streams count.",
		},
	)
	mediaServerOnlineStreams := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "flussonic_server_online_streams",
			Help: "online streams count.",
		},
	)

	registry := prometheus.NewRegistry()
	registry.MustRegister(streamStatus)
	registry.MustRegister(mediaServerUptime)
	registry.MustRegister(mediaServerTotalClients)
	registry.MustRegister(mediaServerTotalStreams)
	registry.MustRegister(mediaServerOnlineStreams)

	err := meta.GetStreamsInfo()
	if err != nil {
		log.Error(err)
	}

	for _, value := range meta.Metrics.FlussonicStreams.Streams {
		s := streamStatus.With(prometheus.Labels{
			"name":           value.Name,
			"title":          value.Title,
			"dvr_expiration": strconv.FormatUint(value.Dvr.Expiration, 10),
		})

		if value.Stats.Alive {
			s.Set(1)
		} else {
			s.Set(0)
		}
	}

	err = meta.GetServerInfo()
	if err != nil {
		log.Error(err)
	}

	mediaServerUptime.Set(float64(meta.Metrics.FlussonicServer.Uptime))
	mediaServerTotalClients.Set(float64(meta.Metrics.FlussonicServer.TotalClients))
	mediaServerTotalStreams.Set(float64(meta.Metrics.FlussonicServer.TotalStreams))
	mediaServerOnlineStreams.Set(float64(meta.Metrics.FlussonicServer.OnlineStreams))

	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
}

func (m *Meta) GetStreamsInfo() error {
	var body []byte

	req, _ := http.NewRequest(
		http.MethodGet,
		fmt.Sprintf("%s/flussonic/api/v3/streams", *m.Flags.Backend),
		nil,
	)

	req.SetBasicAuth(
		m.Config.BasicAuth.Username,
		m.Config.BasicAuth.Password,
	)

	q := req.URL.Query()
	q.Add("limit", strconv.FormatUint(*m.Flags.StreamsRequestLimit, 10))
	req.URL.RawQuery = q.Encode()

	log.Debug("getting /flussonic/api/v3/streams info")

	resp, err := m.Config.Client.Do(req)
	if err != nil {
		return fmt.Errorf("get error: %s", err)
	}
	defer resp.Body.Close()

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("response body reading error: %s", err)
	}

	err = json.Unmarshal(body, &m.Metrics.FlussonicStreams)
	if err != nil {
		return fmt.Errorf("flussonic/api/v3/streams: response body unmarshaling error: %s", err)
	}

	return nil
}

func (m *Meta) GetServerInfo() error {
	var body []byte

	req, _ := http.NewRequest(
		http.MethodGet,
		fmt.Sprintf("%s/flussonic/api/server", *m.Flags.Backend),
		nil,
	)

	req.SetBasicAuth(
		m.Config.BasicAuth.Username,
		m.Config.BasicAuth.Password,
	)

	log.Debug("getting /flussonic/api/server info")

	resp, err := m.Config.Client.Do(req)
	if err != nil {
		return fmt.Errorf("get error: %s", err)
	}
	defer resp.Body.Close()

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("response body reading error: %s", err)
	}

	err = json.Unmarshal(body, &m.Metrics.FlussonicServer)
	if err != nil {
		return fmt.Errorf("api/server: response body unmarshaling error: %s", err)
	}

	return nil
}

func (m *Meta) GetAuth() error {
	c, err := os.Open(*m.Flags.Config)
	if err != nil {
		return fmt.Errorf("media server config file open failed: %s", err)
	}
	defer c.Close()

	regexpAuth := regexp.MustCompile(`(?:^edit_auth\s|\s|;$)`)
	regexpAuthLine := regexp.MustCompile(`^edit_auth`)

	scanner := bufio.NewScanner(c)
	for scanner.Scan() {
		line := scanner.Text()

		if regexpAuthLine.MatchString(line) {
			auth := regexpAuth.Split(line, -1)
			m.Config.BasicAuth.Username, m.Config.BasicAuth.Password = auth[1], auth[2]
		}
	}

	return nil
}

var (
	meta     *Meta
	version  string
	commitID string
)

func init() {
	meta = &Meta{}

	meta.Flags.Addr = flag.String("listen-address", ":9708", "The address to listen on for HTTP requests.")
	meta.Flags.Backend = flag.String("backend-address", "http://localhost:80", "Flussonic media server api address.")
	meta.Flags.InsecureSkipVerify = flag.Bool("insecure-skip-verify", false, "Skip verify cert for Flussonic media server.")
	meta.Flags.Config = flag.String("config-path", "/etc/flussonic/flussonic.conf", "Flussonic media server config path.")
	meta.Flags.Version = flag.Bool("version", false, "Show exporter version.")
	meta.Flags.StreamsRequestLimit = flag.Uint64("streams-request-limit", 10000, "Set limit argument for /flussonic/api/v3/streams request")
	flag.Parse()

	if *meta.Flags.Version {
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		if version != "" {
			fmt.Fprintf(w, "version:\t%s\n", version)
		}
		fmt.Fprintf(w, "git commit:\t%s\n", commitID)
		w.Flush()
		os.Exit(0)
	}

	meta.Config.Client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: *meta.Flags.InsecureSkipVerify,
			},
		},
	}

	err := meta.GetAuth()
	if err != nil {
		log.Fatalf("auth params get failed: %s", err)
	}
}

func main() {
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/probe", probeHandler)
	log.Fatal(http.ListenAndServe(*meta.Flags.Addr, nil))
}
