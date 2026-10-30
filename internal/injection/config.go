package injection

import (
	"fmt"
	"math"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const DefaultModel = "Horizon-Labs/prompt-injection-guard-small@1b7c40f4a5fdbf9622d20372ead279e65d4c7fc9"

type Config struct {
	Provider       string   `json:"provider,omitempty"`
	AllowRemote    bool     `json:"allow_remote,omitempty"`
	Enabled        bool     `json:"enabled"`
	Endpoint       string   `json:"endpoint"`
	Model          string   `json:"model"`
	TokenEnv       string   `json:"token_env"`
	RuntimeDir     string   `json:"runtime_dir"`
	Threshold      float64  `json:"threshold"`
	Action         string   `json:"action"`
	TimeoutSeconds int      `json:"timeout_seconds"`
	MaxInputBytes  int      `json:"max_input_bytes"`
	Sources        []string `json:"sources"`
}

func (c Config) Defaults() Config {
	if c.Provider == "" {
		c.Provider = "local"
	}
	if c.Provider == "jev" {
		if c.Model == "" {
			c.Model = DefaultJevModel
		}
		if c.Endpoint == "" {
			c.Endpoint = JevEndpoint
		}
		if c.TokenEnv == "" {
			c.TokenEnv = "TYPESAFE_API_KEY"
		}
	}
	if c.Model == "" {
		c.Model = DefaultModel
	}
	if c.TokenEnv == "" {
		c.TokenEnv = "GUARD_INJECTION_TOKEN"
	}
	if c.Threshold == 0 {
		c.Threshold = 0.5
	}
	if c.Action == "" {
		c.Action = "block"
	}
	if c.TimeoutSeconds == 0 {
		c.TimeoutSeconds = 30
	}
	if c.MaxInputBytes == 0 {
		c.MaxInputBytes = 262144
	}
	if len(c.Sources) == 0 {
		c.Sources = []string{"prompt", "model_request", "mcp_result"}
	}
	return c
}

func Validate(c Config) error {
	if !c.Enabled {
		return nil
	}
	c = c.Defaults()
	if c.Provider != "local" && c.Provider != "jev" {
		return fmt.Errorf("неизвестный prompt_injection.provider")
	}
	if c.Provider == "jev" {
		if !c.AllowRemote {
			return fmt.Errorf("Jev требует prompt_injection.allow_remote=true для передачи текста TypeSafe")
		}
		if c.Endpoint != JevEndpoint {
			return fmt.Errorf("Jev допускает только https://api.typesafe.ai/v1/systemone")
		}
		if !regexp.MustCompile(`^jev-[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(c.Model) {
			return fmt.Errorf("для Jev требуется закреплённая версия модели, например jev-1.14.0")
		}
	} else {
		u, err := url.Parse(c.Endpoint)
		if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/scan" || u.Port() == "" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "::1") {
			return fmt.Errorf("prompt_injection.endpoint must be an explicit loopback http://127.0.0.1:PORT/scan (or [::1])")
		}
		port, e := strconv.Atoi(u.Port())
		if e != nil || port < 1 || port > 65535 || u.RawPath != "" {
			return fmt.Errorf("invalid classifier endpoint port or path")
		}
	}
	if !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(c.TokenEnv) {
		return fmt.Errorf("invalid classifier token environment name")
	}
	if c.Model == "" || len(c.Model) > 200 || strings.ContainsAny(c.Model, "\r\n\t ") {
		return fmt.Errorf("invalid prompt injection model ID")
	}
	if c.Threshold <= 0 || c.Threshold > 1 || math.IsNaN(c.Threshold) || math.IsInf(c.Threshold, 0) {
		return fmt.Errorf("prompt injection threshold must be in (0,1]")
	}
	if c.Action != "block" && c.Action != "flag" {
		return fmt.Errorf("prompt injection action must be block or flag")
	}
	if c.TimeoutSeconds < 1 || c.TimeoutSeconds > 120 || c.MaxInputBytes < 1 || c.MaxInputBytes > 1<<20 {
		return fmt.Errorf("invalid prompt injection timeout or input limit")
	}
	for _, source := range c.Sources {
		switch source {
		case "prompt", "model_request", "mcp_result", "mcp_arguments":
		default:
			return fmt.Errorf("unknown prompt injection source %q", source)
		}
	}
	return nil
}
