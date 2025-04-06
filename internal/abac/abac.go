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
	states map[string]*state
}

func New(rules map[string]*Rule) (*ABAC, error) {
	abac := &ABAC{Rules: rules, states: make(map[string]*state)}
	for _, condition := range abac.Rules {
		if err := condition.Init(); err != nil {
			return nil, err
		}
	}
	return abac, nil
}

func (a *ABAC) NewState(onABACUpdate func()) string {
	id := uuid.New().String()
	a.mu.Lock()
	a.states[id] = &state{onUpdate: onABACUpdate}
	a.mu.Unlock()
	return id
}

func (a *ABAC) NewStateFrom(stateID string, onABACUpdate func()) string {
	id := uuid.New().String()
	a.mu.Lock()
	if old, ok := a.states[stateID]; ok {
		a.states[id] = old.Copy()
		if onABACUpdate != nil {
			a.states[id].onUpdate = onABACUpdate
		}
	} else {
		a.states[id] = &state{onUpdate: onABACUpdate}
	}
	a.mu.Unlock()
	return id
}

func (a *ABAC) DeleteState(id string) {
	a.mu.Lock()
	delete(a.states, id)
	a.mu.Unlock()
}

func (a *ABAC) Observe(stateID string, events ...Event) (Action, []string, error) {
	a.mu.Lock()
	if _, ok := a.states[stateID]; !ok {
		a.mu.Unlock()
		return 0, nil, ErrUnknownState
	}
	state := a.states[stateID]
	for _, event := range events {
		if err := event(state); err != nil {
			a.mu.Unlock()
			return 0, nil, err
		}
	}
	stateValue := *state
	a.mu.Unlock()
	return a.matchState(stateValue)
}

func (a *ABAC) Update(rules map[string]*Rule) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, condition := range rules {
		if err := condition.Init(); err != nil {
			return err
		}
	}
	a.Rules = rules
	for _, state := range a.states {
		if state.onUpdate != nil {
			go state.onUpdate()
		}
	}
	return nil
}

func (a *ABAC) matchState(state state) (Action, []string, error) {
	var (
		errs         []error
		res          Action
		matchedRules []string
	)
	for name, rule := range a.Rules {
		actions, err := rule.Matches(state)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if actions > 0 {
			matchedRules = append(matchedRules, name)
		}
		res |= actions
	}
	return res, matchedRules, nil
}
