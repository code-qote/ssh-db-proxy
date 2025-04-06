package abac

import (
	"time"

	"ssh-db-proxy/internal/sql"
)

type Event = func(state *state) error

func DatabaseNameEvent(name string) Event {
	return func(state *state) error {
		state.databaseName = optional[string]{name, true}
		return nil
	}
}

func DatabaseUsernameEvent(username string) Event {
	return func(state *state) error {
		state.databaseUsername = optional[string]{username, true}
		return nil
	}
}

func IPEvent(ip string) Event {
	return func(state *state) error {
		state.ip = optional[string]{ip, true}
		return nil
	}
}

func TimeEvent(t time.Time) Event {
	return func(state *state) error {
		state.time = optional[time.Time]{t, true}
		return nil
	}
}

func QueryStatementsEvent(statements []sql.QueryStatement) Event {
	return func(state *state) error {
		state.queryStatements = append(state.queryStatements, statements...)
		return nil
	}
}
