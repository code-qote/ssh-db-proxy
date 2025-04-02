package config

import "ssh-db-proxy/internal/abac"

type Config struct {
	Host               string                `json:"host"`
	Port               string                `json:"port"`
	NoClientAuth       bool                  `yaml:"no_client_auth"`
	HostKeyPrivatePath string                `yaml:"host_key_private_path"`
	UserCAPath         string                `json:"user_ca_path"`
	MITM               MITMConfig            `yaml:"mitm_config"`
	ABACRules          map[string]*abac.Rule `yaml:"abac_rules"`
}

type MITMConfig struct {
	DatabaseCAPath       string `json:"database_ca_path"`
	ClientCAFilePath     string `json:"client_ca_path"`
	ClientPrivateKeyPath string `json:"client_private_key_path"`
}
