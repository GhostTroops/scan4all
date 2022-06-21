package options

type SessionInfo struct {
	ServerURL     string `yaml:"server-url"`
	Token         string `yaml:"server-token"`
	PrivateKey    string `yaml:"private-key"`
	CorrelationID string `yaml:"correlation-id"`
	SecretKey     string `yaml:"secret-key"`
}
