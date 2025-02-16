package config

type TunnelConfig struct {
	Host               string `json:"host"`
	Port               string `json:"port"`
	NoClientAuth       bool   `yaml:"no_client_auth"`
	HostKeyPrivatePath string `yaml:"host_key_private_path"`
	UserCAPath         string `json:"user_ca_path"`
}
