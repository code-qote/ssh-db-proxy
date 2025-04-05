package abac

import (
	"errors"
	"sync"

	"github.com/google/uuid"
)

var (
	ErrUnknownState = errors.New(`unknown state`)
)

type ABAC struct {
	Rules map[string]*Rule `yaml:"rules"`

	mu     sync.Mutex
	states map[string]*State
}

func New(rules map[string]*Rule) (*ABAC, error) {
	abac := &ABAC{Rules: rules, states: make(map[string]*State)}
	for _, condition := range abac.Rules {
		if err := condition.Init(); err != nil {
			return nil, err
		}
	}
	return abac, nil
}

func (a *ABAC) NewState() string {
	id := uuid.New().String()
	a.mu.Lock()
	a.states[id] = &State{}
	a.mu.Unlock()
	return id
}

func (a *ABAC) NewStateFrom(stateID string) string {
	id := uuid.New().String()
	a.mu.Lock()
	if old, ok := a.states[stateID]; ok {
		a.states[id] = old.Copy()
	} else {
		a.states[id] = &State{}
	}
	a.mu.Unlock()
	return id
}

func (a *ABAC) DeleteState(id string) {
	a.mu.Lock()
	delete(a.states, id)
	a.mu.Unlock()
}

func (a *ABAC) Observe(stateID string, events ...Event) (Action, error) {
	a.mu.Lock()
	if _, ok := a.states[stateID]; !ok {
		a.mu.Unlock()
		return 0, ErrUnknownState
	}
	state := a.states[stateID]
	for _, event := range events {
		if err := event(state); err != nil {
			a.mu.Unlock()
			return 0, err
		}
	}
	stateValue := *state
	a.mu.Unlock()
	return a.validateState(stateValue)
}

func (a *ABAC) validateState(state State) (Action, error) {
	var (
		errs []error
		res  Action
	)
	for _, rule := range a.Rules {
		actions, err := rule.Matches(state)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		res |= actions
	}
	return res, nil
}
