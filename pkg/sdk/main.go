package sdk

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/sputnik-systems/flussonic_exporter/pkg/sdk/storage"
	v3 "github.com/sputnik-systems/flussonic_exporter/pkg/sdk/storage/v3"
)

type Client struct {
	addr       string
	apiVersion string
	auth       clientBasicAuth
	http       *http.Client
}

type clientBasicAuth struct {
	user string
	pass string
}

func NewStreamerClient(addr string, opts ...ClientOption) *Client {
	c := &Client{addr: addr, apiVersion: "v3", http: &http.Client{}}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

type ClientOption func(*Client)

func WithInsecureSkipVerify() ClientOption {
	return func(c *Client) {
		c.http = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}
	}
}

func WithBasicAuth(username, password string) ClientOption {
	return func(c *Client) {
		c.auth = clientBasicAuth{
			user: username,
			pass: password,
		}
	}
}

func (c *Client) GetConfigStats() (storage.ConfigStats, error) {
	addr := fmt.Sprintf("%s/streamer/api/%s/config/stats", c.addr, c.apiVersion)
	req, _ := http.NewRequest(http.MethodGet, addr, nil)

	req.SetBasicAuth(c.auth.user, c.auth.pass)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get error: %s", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("response body reading error: %s", err)
	}

	var stats storage.ConfigStats
	switch c.apiVersion {
	default:
		stats = &v3.ConfigStats{}
		err = json.Unmarshal(body, stats)
		if err != nil {
			return nil, fmt.Errorf("streamer/api/v3/config/stats: response body unmarshaling error: %s", err)
		}
	}

	return stats, nil
}

func (c *Client) GetStreams(cursor string) (storage.Streams, error) {
	addr := fmt.Sprintf("%s/streamer/api/%s/streams", c.addr, c.apiVersion)
	req, _ := http.NewRequest(http.MethodGet, addr, nil)

	req.SetBasicAuth(c.auth.user, c.auth.pass)

	q := req.URL.Query()
	q.Add("limit", strconv.Itoa(1000))
	q.Add("cursor", cursor)
	req.URL.RawQuery = q.Encode()

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get error: %s", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("response body reading error: %s", err)
	}

	var streams storage.Streams
	switch c.apiVersion {
	default:
		streams = &v3.Streams{}
		err = json.Unmarshal(body, streams)
		if err != nil {
			return nil, fmt.Errorf("streamer/api/v3/streams: response body unmarshaling error: %s", err)
		}
	}

	return streams, nil
}
