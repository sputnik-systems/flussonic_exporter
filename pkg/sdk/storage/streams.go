package storage

type Streams interface {
	GetNext() string
	GetPrev() string
	ListStreams() []Stream
}

type Stream interface {
	GetName() string
	GetTitle() string
	GetDvr() StreamDvr
	GetStats() StreamStats
}

type StreamDvr interface {
	GetExpiration() uint64
}

type StreamStats interface {
	GetAgentStatus() string
	GetAlive() bool
	GetRetryCount() uint64
}
