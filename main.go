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
	Addr               *string
	Backend            *string
	InsecureSkipVerify *bool
	Config             *string
	Version            *bool
}

type Metrics struct {
	Media  FlussonicMedia
	Server FlussonicServer
}

type FlussonicMedia []FlussonicMediaItem

type FlussonicMediaItem struct {
	Entry string
	Value FlussonicMediaValue
}

type FlussonicMediaValue struct {
	Name    string
	Stats   FlussonicMediaValueStats
	Options FlussonicMediaValueOptions
}

type FlussonicMediaValueStats struct {
	AgentStatus string
	Alive       bool
	RetryCount  uint64
}

type FlussonicMediaValueOptions struct {
	Dvr   FlussonicMediaValueOptionsDvr
	Title string `json:title`
}

type FlussonicMediaValueOptionsDvr struct {
	DvrLimit uint64 `json:"dvr_limit"`
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
			Name: "flussonic_media_stream_status",
			Help: "flussonic streams status.",
		},
		[]string{"name", "title", "dvr_limit"},
	)
	// mediaServerStatus := prometheus.NewGauge(
	// 	prometheus.GaugeOpts{
	// 		Name: "flussonic_server_status",
	// 		Help: "This metric mirror flussonic stream status.",
	// 	},
	// 	[]string{"name", "dvr_limit"},
	// )
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
	// registry.MustRegister(mediaServerStatus)
	registry.MustRegister(mediaServerUptime)
	registry.MustRegister(mediaServerTotalClients)
	registry.MustRegister(mediaServerTotalStreams)
	registry.MustRegister(mediaServerOnlineStreams)

	meta.Metrics.Media = FlussonicMedia{}
	meta.Metrics.Server = FlussonicServer{}

	err := meta.GetMediaInfo()
	if err != nil {
		log.Error(err)
	}

	for _, value := range meta.Metrics.Media {
		if value.Entry == "stream" {
			s := streamStatus.With(prometheus.Labels{
				"name":      value.Value.Name,
				"title":     value.Value.Options.Title,
				"dvr_limit": strconv.FormatUint(value.Value.Options.Dvr.DvrLimit, 10),
			})

			if value.Value.Stats.Alive {
				s.Set(1)
			} else {
				s.Set(0)
			}
		}
	}

	err = meta.GetServerInfo()
	if err != nil {
		log.Error(err)
	}

	mediaServerUptime.Set(float64(meta.Metrics.Server.Uptime))
	mediaServerTotalClients.Set(float64(meta.Metrics.Server.TotalClients))
	mediaServerTotalStreams.Set(float64(meta.Metrics.Server.TotalStreams))
	mediaServerOnlineStreams.Set(float64(meta.Metrics.Server.OnlineStreams))

	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
}

func (m *Meta) GetMediaInfo() error {
	body, err := m.makeRequest("media")
	if err != nil {
		return fmt.Errorf("api/media: %s", err)
	}

	err = json.Unmarshal(body, &m.Metrics.Media)
	if err != nil {
		return fmt.Errorf("api/media: response body unmarshaling error: %s", err)
	}

	return nil
}

func (m *Meta) GetServerInfo() error {
	body, err := m.makeRequest("server")
	if err != nil {
		return fmt.Errorf("api/server: %s", err)
	}

	err = json.Unmarshal(body, &m.Metrics.Server)
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

	regexpAuth := regexp.MustCompile(`(?:^view_auth\s|\s|;$)`)
	regexpAuthLine := regexp.MustCompile(`^view_auth`)

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

func (m *Meta) makeRequest(path string) ([]byte, error) {
	var body []byte

	req, _ := http.NewRequest(
		http.MethodGet,
		fmt.Sprintf("%s/flussonic/api/%s", *m.Flags.Backend, path),
		nil,
	)

	req.SetBasicAuth(
		m.Config.BasicAuth.Username,
		m.Config.BasicAuth.Password,
	)

	log.Debugf("getting %s info", path)

	resp, err := m.Config.Client.Do(req)
	if err != nil {
		return body, fmt.Errorf("get error: %s", err)
	}
	defer resp.Body.Close()

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return body, fmt.Errorf("response body reading error: %s", err)
	}

	return body, nil
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
