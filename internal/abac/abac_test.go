package abac

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestABAC(t *testing.T) {
	const (
		matchingIP    = "416a:707c:06b9:8143:2d47:763b:2273:4933"
		notMatchingIP = "416a:707c:aaaa:8143:2d47:763b:2273:4933"
	)

	t.Run("no-state", func(t *testing.T) {
		abac, err := New(nil)
		require.NoError(t, err)

		actions, _, err := abac.Observe("unknown", DatabaseNameEvent("name"))
		require.EqualError(t, err, ErrUnknownState.Error())
		require.Empty(t, actions)
	})

	t.Run("database-name-condition", func(t *testing.T) {
		rules := map[string]*Rule{
			"rule1": {
				Conditions: []Condition{&DatabaseNameCondition{Regexps: []string{"a.*"}}},
				Actions:    Notify,
			},
		}
		abac, err := New(rules)
		require.NoError(t, err)

		stateID := abac.NewState(nil)
		actions, names, err := abac.Observe(stateID, DatabaseNameEvent("bbb"))
		require.NoError(t, err)
		require.Empty(t, actions)
		require.Empty(t, names)

		actions, names, err = abac.Observe(stateID, DatabaseNameEvent("aaa"))
		require.NoError(t, err)
		require.Equal(t, rules["rule1"].Actions, actions)
		require.ElementsMatch(t, names, []string{"rule1"})

	})

	t.Run("database-username-condition", func(t *testing.T) {
		rules := map[string]*Rule{
			"rule1": {
				Conditions: []Condition{&DatabaseUsernameCondition{Regexps: []string{"a.*"}}},
				Actions:    Notify,
			},
		}
		abac, err := New(rules)
		require.NoError(t, err)

		stateID := abac.NewState(nil)
		actions, _, err := abac.Observe(stateID, DatabaseUsernameEvent("bbb"))
		require.NoError(t, err)
		require.Empty(t, actions)

		actions, _, err = abac.Observe(stateID, DatabaseUsernameEvent("aaa"))
		require.NoError(t, err)
		require.Equal(t, rules["rule1"].Actions, actions)
	})

	t.Run("ip-condition", func(t *testing.T) {
		rules := map[string]*Rule{
			"rule1": {
				Conditions: []Condition{&IPCondition{Subnets: []string{"416a:707c:06b9:8143::/64"}}},
				Actions:    Notify,
			},
		}
		abac, err := New(rules)
		require.NoError(t, err)

		stateID := abac.NewState(nil)
		actions, _, err := abac.Observe(stateID, IPEvent(notMatchingIP))
		require.NoError(t, err)
		require.Empty(t, actions)

		actions, _, err = abac.Observe(stateID, IPEvent(matchingIP))
		require.NoError(t, err)
		require.Equal(t, rules["rule1"].Actions, actions)
	})

	t.Run("time-condition", func(t *testing.T) {
		rules := map[string]*Rule{
			"rule1": {
				Conditions: []Condition{
					&TimeCondition{
						Hour: []Interval{{
							From: 7,
							To:   17,
						},
						},
					},
				},
				Actions: Notify,
			},
		}
		abac, err := New(rules)
		require.NoError(t, err)

		location, err := time.LoadLocation("Europe/Moscow")
		require.NoError(t, err)

		stateID := abac.NewState(nil)
		actions, _, err := abac.Observe(stateID, TimeEvent(time.Date(2025, time.January, 1, 9, 0, 0, 0, location)))
		require.NoError(t, err)
		require.Empty(t, actions)

		actions, _, err = abac.Observe(stateID, TimeEvent(time.Date(2025, time.January, 1, 11, 0, 0, 0, location)))
		require.NoError(t, err)
		require.Equal(t, rules["rule1"].Actions, actions)
	})

	t.Run("single-rule", func(t *testing.T) {
		rules := map[string]*Rule{
			"rule1": {
				Conditions: []Condition{
					&DatabaseNameCondition{Regexps: []string{"a.*"}},
					&IPCondition{Subnets: []string{"416a:707c:06b9:8143::/64"}},
				},
				Actions: Notify | NotPermit,
			},
		}
		abac, err := New(rules)
		require.NoError(t, err)

		stateID := abac.NewState(nil)

		actions, _, err := abac.Observe(stateID, DatabaseNameEvent("bbb"))
		require.NoError(t, err)
		require.Empty(t, actions)

		actions, _, err = abac.Observe(stateID, IPEvent(matchingIP))
		require.NoError(t, err)
		require.Empty(t, actions)

		actions, _, err = abac.Observe(stateID, DatabaseNameEvent("aaaa"))
		require.NoError(t, err)
		require.Equal(t, rules["rule1"].Actions, actions)
	})

	t.Run("intersect-rules", func(t *testing.T) {
		rules := map[string]*Rule{
			"rule1": {
				Conditions: []Condition{&DatabaseNameCondition{Regexps: []string{"a.*"}}},
				Actions:    Notify | NotPermit,
			},
			"rule2": {
				Conditions: []Condition{
					&DatabaseNameCondition{Regexps: []string{".*"}},
				},
				Actions: Notify | Disconnect,
			},
		}
		abac, err := New(rules)
		require.NoError(t, err)

		stateID := abac.NewState(nil)
		actions, names, err := abac.Observe(stateID, DatabaseNameEvent("abracadabra"), TimeEvent(time.Now()))
		require.NoError(t, err)
		require.Equal(t, Notify|NotPermit|Disconnect, actions)
		require.ElementsMatch(t, names, []string{"rule1", "rule2"})
	})
}
