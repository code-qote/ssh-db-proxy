package metadata

type Metadata struct {
	ConnectionID     string `json:"connection_id"`
	RequestID        string `json:"request_id"`
	StateID          string `json:"state_id"`
	RemoteAddr       string `json:"remote_addr"`
	DatabaseName     string `json:"database_name"`
	DatabaseUsername string `json:"database_username"`
}
