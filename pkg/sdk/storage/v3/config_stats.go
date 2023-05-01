package v3

type ConfigStats struct {
	Uptime        uint64
	TotalClients  uint64 `json:"total_clients"`
	TotalStreams  uint64 `json:"total_streams"`
	OnlineStreams uint64 `json:"online_streams"`
}

func (cs *ConfigStats) GetUptime() uint64 {
	return cs.Uptime
}

func (cs *ConfigStats) GetTotalClients() uint64 {
	return cs.TotalClients
}

func (cs *ConfigStats) GetTotalStreams() uint64 {
	return cs.TotalStreams
}

func (cs *ConfigStats) GetOnlineStreams() uint64 {
	return cs.OnlineStreams
}
