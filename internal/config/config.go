package config

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"

	"ssh-db-proxy/internal/abac"
)

var ErrConfigNotChanged = errors.New("config not changed")

type Config struct {
	Host               string                                `json:"host"`
	Port               string                                `json:"port"`
	NoClientAuth       bool                                  `yaml:"no_client_auth"`
	HostKeyPrivatePath string                                `yaml:"host_key_private_path"`
	UserCAPath         string                                `json:"user_ca_path"`
	MITM               MITMConfig                            `yaml:"mitm_config"`
	ABACRulesConfig    map[string]ABACRule                   `yaml:"abac_rules"`
	ABACRules          atomic.Pointer[map[string]*abac.Rule] `yaml:"-"`
	HotReload          HotReload                             `yaml:"hot_reload"`
	ConfigPath         string                                `yaml:"-"`

	checksum []byte
}

type MITMConfig struct {
	DatabaseCAPath       string `yaml:"database_ca_path"`
	ClientCAFilePath     string `yaml:"client_ca_path"`
	ClientPrivateKeyPath string `yaml:"client_private_key_path"`
}

type ABACRule struct {
	Conditions []ABACCondition `yaml:"conditions"`
	Actions    ABACActions     `yaml:"actions"`
}

type ABACCondition struct {
	DatabaseName     *abac.DatabaseNameCondition     `yaml:"database_name"`
	DatabaseUsername *abac.DatabaseUsernameCondition `yaml:"database_username"`
	IPCondition      *abac.IPCondition               `yaml:"ip"`
	QueryCondition   *abac.QueryCondition            `yaml:"query"`
	TimeCondition    *abac.TimeCondition             `yaml:"time"`
}

type ABACActions struct {
	Notify     bool `yaml:"notify"`
	NotPermit  bool `yaml:"not_permit"`
	Disconnect bool `yaml:"disconnect"`
}

type HotReload struct {
	Enabled bool          `yaml:"enabled"`
	Period  time.Duration `yaml:"period"`
}

func LoadConfig(path string, oldConfig *Config) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}
	sha := sha256.New()
	if _, err := io.Copy(sha, bytes.NewReader(data)); err != nil {
		return nil, fmt.Errorf("hash config file: %w", err)
	}
	checksum := sha.Sum(nil)
	if oldConfig != nil {
		if bytes.Equal(oldConfig.checksum, checksum) {
			return oldConfig, ErrConfigNotChanged
		}
	}

	var (
		readConfig Config
		newConfig  *Config
	)
	if err := yaml.Unmarshal(data, &readConfig); err != nil {
		return nil, fmt.Errorf("unmarshal config file: %w", err)
	}

	if oldConfig != nil {
		newConfig = &Config{
			Host:               oldConfig.Host,
			Port:               oldConfig.Port,
			NoClientAuth:       oldConfig.NoClientAuth,
			HostKeyPrivatePath: oldConfig.HostKeyPrivatePath,
			UserCAPath:         oldConfig.UserCAPath,
			MITM:               oldConfig.MITM,
			ABACRulesConfig:    readConfig.ABACRulesConfig,
			HotReload:          readConfig.HotReload,
		}
	} else {
		newConfig = &readConfig
	}

	if err := validateConfig(newConfig); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	buildABACRules(newConfig)
	newConfig.checksum = checksum
	newConfig.ConfigPath = path

	return newConfig, nil
}

func validateConfig(config *Config) error {
	if config.HotReload.Enabled {
		if config.HotReload.Period <= 0 {
			return fmt.Errorf("hot reload period must be greater than zero")
		}
	}
	for ruleName, rule := range config.ABACRulesConfig {
		for _, condition := range rule.Conditions {
			notNil := 0
			if condition.DatabaseName != nil {
				notNil++
			}
			if condition.DatabaseUsername != nil {
				notNil++
			}
			if condition.IPCondition != nil {
				notNil++
			}
			if condition.QueryCondition != nil {
				notNil++
			}
			if condition.TimeCondition != nil {
				notNil++
			}
			if notNil == 0 {
				return fmt.Errorf("rule %s must have at least one condition", ruleName)
			}
			if notNil > 1 {
				return fmt.Errorf("rule %s must have at most one condition", ruleName)
			}
		}
	}
	return nil
}

func buildABACRules(config *Config) {
	abacRules := make(map[string]*abac.Rule, len(config.ABACRulesConfig))
	for ruleName, rule := range config.ABACRulesConfig {
		abacRules[ruleName] = &abac.Rule{}
		for _, condition := range rule.Conditions {
			if condition.DatabaseName != nil {
				abacRules[ruleName].Conditions = append(abacRules[ruleName].Conditions, condition.DatabaseName)
			}
			if condition.DatabaseUsername != nil {
				abacRules[ruleName].Conditions = append(abacRules[ruleName].Conditions, condition.DatabaseUsername)
			}
			if condition.IPCondition != nil {
				abacRules[ruleName].Conditions = append(abacRules[ruleName].Conditions, condition.IPCondition)
			}
			if condition.QueryCondition != nil {
				abacRules[ruleName].Conditions = append(abacRules[ruleName].Conditions, condition.QueryCondition)
			}
			if condition.TimeCondition != nil {
				abacRules[ruleName].Conditions = append(abacRules[ruleName].Conditions, condition.TimeCondition)
			}
		}
		if rule.Actions.Notify {
			abacRules[ruleName].Actions |= abac.Notify
		}
		if rule.Actions.NotPermit {
			abacRules[ruleName].Actions |= abac.NotPermit
		}
		if rule.Actions.Disconnect {
			abacRules[ruleName].Actions |= abac.Disconnect
		}
	}
	config.ABACRules.Store(&abacRules)
}
