package abac

import (
	"time"

	"ssh-db-proxy/internal/sql"
)

type Event = func(state *State) error

func DatabaseNameEvent(name string) Event {
	return func(state *State) error {
		state.DatabaseName = optional[string]{name, true}
		return nil
	}
}

func DatabaseUsernameEvent(username string) Event {
	return func(state *State) error {
		state.DatabaseUsername = optional[string]{username, true}
		return nil
	}
}

func IPEvent(ip string) Event {
	return func(state *State) error {
		state.IP = optional[string]{ip, true}
		return nil
	}
}

func TimeEvent(t time.Time) Event {
	return func(state *State) error {
		state.Time = optional[time.Time]{t, true}
		return nil
	}
}

func QueryStatementsEvent(statements []sql.QueryStatement) Event {
	return func(state *State) error {
		state.QueryStatements = append(state.QueryStatements, statements...)
		return nil
	}
}
