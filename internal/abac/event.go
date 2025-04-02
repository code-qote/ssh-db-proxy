package abac

import "time"

type Event = func(state *State) error

func DatabaseNameEvent(name string) Event {
	return func(state *State) error {
		state.DatabaseName = name
		return nil
	}
}

func DatabaseUsernameEvent(username string) Event {
	return func(state *State) error {
		state.DatabaseUsername = username
		return nil
	}
}

func IPEvent(ip string) Event {
	return func(state *State) error {
		state.IP = ip
		return nil
	}
}

func TimeEvent(t time.Time) Event {
	return func(state *State) error {
		state.Time = t
		return nil
	}
}
