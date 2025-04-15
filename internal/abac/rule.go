package abac

import (
	"fmt"
	"math"
	"net"
	"regexp"
	"strings"
	"time"

	"ssh-db-proxy/internal/sql"
)

type Action int

const (
	NotPermit Action = 1 << iota
	Disconnect
	Notify
)

var validMonths = map[string]time.Month{
	"january":   time.January,
	"february":  time.February,
	"march":     time.March,
	"april":     time.April,
	"may":       time.May,
	"june":      time.June,
	"july":      time.July,
	"august":    time.August,
	"september": time.September,
	"october":   time.October,
	"november":  time.November,
	"december":  time.December,
}

var validWeekdays = map[string]time.Weekday{
	"monday":    time.Monday,
	"tuesday":   time.Tuesday,
	"wednesday": time.Wednesday,
	"thursday":  time.Thursday,
	"friday":    time.Friday,
	"saturday":  time.Saturday,
	"sunday":    time.Sunday,
}

type Condition interface {
	Init() error
	Matches(state) bool
}

type Rule struct {
	Conditions []Condition `yaml:"conditions"`
	Actions    Action      `yaml:"actions"`
}

func (c *Rule) Init() error {
	if c == nil {
		return nil
	}
	for _, condition := range c.Conditions {
		if err := condition.Init(); err != nil {
			return err
		}
	}
	return nil
}

func (c *Rule) Matches(state state) (Action, error) {
	if c == nil {
		return 0, nil
	}
	matches := true
	for _, condition := range c.Conditions {
		matches = matches && condition.Matches(state)
	}
	if matches {
		return c.Actions, nil
	}
	return 0, nil
}

type IPCondition struct {
	Subnets []string `yaml:"subnets"`
	subnets []*net.IPNet
}

func (c *IPCondition) Init() error {
	if c == nil {
		return nil
	}
	c.subnets = make([]*net.IPNet, 0, len(c.Subnets))
	for _, subnet := range c.Subnets {
		_, cidr, err := net.ParseCIDR(subnet)
		if err != nil {
			return err
		}
		c.subnets = append(c.subnets, cidr)
	}
	return nil
}

func (c *IPCondition) Matches(state state) bool {
	if c == nil {
		return false
	}
	if !state.ip.set {
		return false
	}
	ipAddr, err := net.ResolveIPAddr("ip6", state.ip.value)
	if err != nil {
		ipAddr, err = net.ResolveIPAddr("ip", state.ip.value)
		if err != nil {
			return false
		}
	}

	for _, subnet := range c.subnets {
		if subnet.Contains(ipAddr.IP) {
			return true
		}
	}
	return false
}

type DatabaseUsernameCondition struct {
	Regexps []string `yaml:"regexps"`
	regexps []*regexp.Regexp
}

func (c *DatabaseUsernameCondition) Init() error {
	if c == nil {
		return nil
	}
	c.regexps = make([]*regexp.Regexp, 0, len(c.Regexps))
	for _, reg := range c.Regexps {
		if !strings.HasPrefix(reg, "^") {
			reg = "^" + reg
		}
		if !strings.HasSuffix(reg, "$") {
			reg = reg + "$"
		}
		compiled, err := regexp.Compile(reg)
		if err != nil {
			return err
		}
		c.regexps = append(c.regexps, compiled)
	}
	return nil
}

func (c *DatabaseUsernameCondition) Matches(state state) bool {
	if c == nil {
		return false
	}
	if !state.databaseUsername.set {
		return false
	}
	for _, reg := range c.regexps {
		if reg.MatchString(state.databaseUsername.value) {
			return true
		}
	}
	return false
}

type DatabaseNameCondition struct {
	Regexps []string `yaml:"regexps"`
	regexps []*regexp.Regexp
}

func (c *DatabaseNameCondition) Init() error {
	if c == nil {
		return nil
	}
	c.regexps = make([]*regexp.Regexp, 0, len(c.Regexps))
	for _, reg := range c.Regexps {
		if !strings.HasPrefix(reg, "^") {
			reg = "^" + reg
		}
		if !strings.HasSuffix(reg, "$") {
			reg = reg + "$"
		}
		compiled, err := regexp.Compile(reg)
		if err != nil {
			return err
		}
		c.regexps = append(c.regexps, compiled)
	}
	return nil
}

func (c *DatabaseNameCondition) Matches(state state) bool {
	if c == nil {
		return false
	}
	if !state.databaseName.set {
		return false
	}
	for _, reg := range c.regexps {
		if reg.MatchString(state.databaseName.value) {
			return true
		}
	}
	return false
}

type TimeCondition struct {
	Year     []Interval `yaml:"year"`
	Month    []string   `yaml:"month"`
	Day      []Interval `yaml:"day"`
	Hour     []Interval `yaml:"hour"`
	Minute   []Interval `yaml:"minute"`
	Second   []Interval `yaml:"second"`
	Weekday  []string   `yaml:"weekday"`
	Location string     `yaml:"location"`
	location *time.Location
}

type Interval struct {
	From int `yaml:"from"`
	To   int `yaml:"to"`
}

func (c *Interval) Init(min, max int) error {
	if c == nil {
		return nil
	}
	if c.From > c.To {
		return fmt.Errorf("from must be greater than to")
	}
	if c.From < min {
		return fmt.Errorf("from must be greater than %d", min)
	}
	if c.To > max {
		return fmt.Errorf("to must be less than %d", max)
	}
	return nil
}

func (c *Interval) Matches(v int) bool {
	if c == nil {
		return true
	}
	return c.From <= v && v <= c.To
}

func (c *TimeCondition) Init() error {
	if c == nil {
		return nil
	}
	location, err := time.LoadLocation(c.Location)
	if err != nil {
		return err
	}
	c.location = location
	for _, weekday := range c.Weekday {
		if _, ok := validWeekdays[weekday]; !ok {
			return fmt.Errorf("invalid weekday: %s", weekday)
		}
	}
	for _, month := range c.Month {
		if _, ok := validMonths[month]; !ok {
			return fmt.Errorf("invalid month: %s", month)
		}
	}
	for _, interval := range c.Year {
		if err := interval.Init(0, math.MaxInt); err != nil {
			return fmt.Errorf("init year interval: %w", err)
		}
	}
	for _, interval := range c.Day {
		if err := interval.Init(1, 31); err != nil {
			return fmt.Errorf("init day interval: %w", err)
		}
	}
	for _, interval := range c.Hour {
		if err := interval.Init(0, 23); err != nil {
			return fmt.Errorf("init hour interval: %w", err)
		}
	}
	for _, interval := range c.Minute {
		if err := interval.Init(0, 59); err != nil {
			return fmt.Errorf("init minute interval: %w", err)
		}
	}
	for _, interval := range c.Second {
		if err := interval.Init(0, 59); err != nil {
			return fmt.Errorf("init second interval: %w", err)
		}
	}
	return nil
}

func (c *TimeCondition) Matches(state state) bool {
	if c == nil {
		return false
	}
	if !state.time.set {
		return false
	}
	t := state.time.value.In(c.location)

	if len(c.Weekday) > 0 {
		weekdayMatches := false
		for _, weekday := range c.Weekday {
			if validWeekdays[weekday] == t.Weekday() {
				weekdayMatches = true
				break
			}
		}
		if !weekdayMatches {
			return false
		}
	}
	if len(c.Month) > 0 {
		monthMatches := false
		for _, month := range c.Month {
			if validMonths[month] == t.Month() {
				monthMatches = true
				break
			}
		}
		if !monthMatches {
			return false
		}
	}
	if len(c.Year) > 0 {
		yearMatches := false
		for _, year := range c.Year {
			if year.Matches(t.Year()) {
				yearMatches = true
				break
			}
		}
		if !yearMatches {
			return false
		}
	}
	if len(c.Day) > 0 {
		dayMatches := false
		for _, day := range c.Day {
			if day.Matches(t.Day()) {
				dayMatches = true
				break
			}
		}
		if !dayMatches {
			return false
		}
	}
	if len(c.Hour) > 0 {
		hourMatches := false
		for _, hour := range c.Hour {
			if hour.Matches(t.Hour()) {
				hourMatches = true
				break
			}
		}
		if !hourMatches {
			return false
		}
	}
	if len(c.Minute) > 0 {
		minuteMatches := false
		for _, minute := range c.Minute {
			if minute.Matches(t.Minute()) {
				minuteMatches = true
				break
			}
		}
		if !minuteMatches {
			return false
		}
	}
	if len(c.Second) > 0 {
		secondMatches := false
		for _, second := range c.Second {
			if second.Matches(t.Second()) {
				secondMatches = true
				break
			}
		}
		if !secondMatches {
			return false
		}
	}
	return true
}

type QueryCondition struct {
	StatementType string   `yaml:"statement_type"`
	TableRegexps  []string `yaml:"table_regexps"`
	ColumnRegexps []string `yaml:"column_regexps"`
	Strict        bool     `yaml:"strict"`

	statementType sql.StatementType `yaml:"-"`
	tableRegexps  []*regexp.Regexp  `yaml:"-"`
	columnRegexps []*regexp.Regexp  `yaml:"-"`
}

func (c *QueryCondition) Init() error {
	if c.StatementType != "" {
		typ, ok := sql.StatementTypeByString[c.StatementType]
		if !ok {
			return fmt.Errorf("invalid statement type: %s", c.StatementType)
		}
		c.statementType = typ
	}
	for _, tableRegexp := range c.TableRegexps {
		re, err := regexp.Compile(tableRegexp)
		if err != nil {
			return err
		}
		c.tableRegexps = append(c.tableRegexps, re)
	}
	for _, columnRegexp := range c.ColumnRegexps {
		re, err := regexp.Compile(columnRegexp)
		if err != nil {
			return err
		}
		c.columnRegexps = append(c.columnRegexps, re)
	}
	return nil
}

func (c *QueryCondition) Matches(state state) bool {
	for _, statement := range state.queryStatements {
		if c.statementType != sql.NoOp {
			if statement.Type != c.statementType {
				continue
			}
		}
		tableMatches := false
		for _, tableRegexp := range c.tableRegexps {
			if tableRegexp.MatchString(statement.Table) {
				tableMatches = true
				break
			}
		}
		columnMatches := false
		for _, columnRegexp := range c.columnRegexps {
			if columnRegexp.MatchString(statement.Column) {
				columnMatches = true
				break
			}
		}
		if columnMatches && tableMatches {
			return true
		}
		if statement.Column == "" && statement.Table != "" && tableMatches && c.Strict {
			return true
		}
	}
	return false
}
