package metadata

type Metadata struct {
	ConnectionID     string           `json:"connection_id"`
	RequestID        string           `json:"request_id"`
	StateID          string           `json:"state_id"`
	RemoteAddr       string           `json:"remote_addr"`
	DatabaseName     string           `json:"database_name"`
	DatabaseUsername string           `json:"database_username"`
	Query            string           `json:"query"`
	QueryStatements  []QueryStatement `json:"query_statements"`
}

func (m *Metadata) Copy() Metadata {
	queryStatements := make([]QueryStatement, len(m.QueryStatements))
	copy(queryStatements, m.QueryStatements)
	return Metadata{
		ConnectionID:     m.ConnectionID,
		RequestID:        m.RequestID,
		StateID:          m.StateID,
		RemoteAddr:       m.RemoteAddr,
		DatabaseName:     m.DatabaseName,
		DatabaseUsername: m.DatabaseUsername,
		QueryStatements:  queryStatements,
	}
}

type QueryStatement struct {
	StatementType string `json:"statement_type"`
	Table         string `json:"table"`
	Column        string `json:"column"`
}
