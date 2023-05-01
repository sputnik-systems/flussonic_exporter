package v3

import (
	"github.com/sputnik-systems/flussonic_exporter/pkg/sdk/storage"
)

type Streams struct {
	Next    string
	Prev    string
	Streams []*Stream
}

type Stream struct {
	Name  string
	Title string
	Dvr   StreamDvr
	Stats StreamStats
}

type StreamDvr struct {
	Expiration uint64
}

type StreamStats struct {
	AgentStatus string
	Alive       bool
	RetryCount  uint64
}

func (s *Streams) GetNext() string {
	return s.Next
}

func (s *Streams) GetPrev() string {
	return s.Prev
}

func (s *Streams) ListStreams() []storage.Stream {
	streams := make([]storage.Stream, 0)
	for _, stream := range s.Streams {
		streams = append(streams, stream)
	}

	return streams
}

func (s *Stream) GetName() string {
	return s.Name
}

func (s *Stream) GetTitle() string {
	return s.Title
}

func (s *Stream) GetDvr() storage.StreamDvr {
	return &s.Dvr
}

func (s *Stream) GetStats() storage.StreamStats {
	return &s.Stats
}

func (d *StreamDvr) GetExpiration() uint64 {
	return d.Expiration
}

func (s *StreamStats) GetAgentStatus() string {
	return s.AgentStatus
}

func (s *StreamStats) GetAlive() bool {
	return s.Alive
}

func (s *StreamStats) GetRetryCount() uint64 {
	return s.RetryCount
}
