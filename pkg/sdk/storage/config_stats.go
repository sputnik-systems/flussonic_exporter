package storage

type ConfigStats interface {
	GetUptime() uint64
	GetTotalClients() uint64
	GetTotalStreams() uint64
	GetOnlineStreams() uint64
}
