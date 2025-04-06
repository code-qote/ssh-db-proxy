package abac

import (
	"time"

	"ssh-db-proxy/internal/sql"
)

type optional[T any] struct {
	value T
	set   bool
}

type State struct {
	DatabaseUsername optional[string]
	IP               optional[string]
	DatabaseName     optional[string]
	Time             optional[time.Time]
	QueryStatements  []sql.QueryStatement
}

func (s *State) Copy() *State {
	queryStatements := make([]sql.QueryStatement, len(s.QueryStatements))
	copy(queryStatements, s.QueryStatements)
	return &State{
		DatabaseUsername: s.DatabaseUsername,
		IP:               s.IP,
		DatabaseName:     s.DatabaseName,
		Time:             s.Time,
		QueryStatements:  queryStatements,
	}
}
