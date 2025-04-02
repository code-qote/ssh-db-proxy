package abac

import "time"

type State struct {
	DatabaseUsername string
	IP               string
	DatabaseName     string
	Time             time.Time
}
