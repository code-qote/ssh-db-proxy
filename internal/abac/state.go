package abac

import (
	"time"

	"ssh-db-proxy/internal/sql"
)

type optional[T any] struct {
	value T
	set   bool
}

type state struct {
	databaseUsername optional[string]
	ip               optional[string]
	databaseName     optional[string]
	time             optional[time.Time]
	queryStatements  []sql.QueryStatement

	onUpdate func()
}

func (s *state) Copy() *state {
	queryStatements := make([]sql.QueryStatement, len(s.queryStatements))
	copy(queryStatements, s.queryStatements)
	return &state{
		databaseUsername: s.databaseUsername,
		ip:               s.ip,
		databaseName:     s.databaseName,
		time:             s.time,
		queryStatements:  queryStatements,
		onUpdate:         s.onUpdate,
	}
}
