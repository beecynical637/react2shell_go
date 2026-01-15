package config

import (
	"os"
	"strconv"
	"time"
)

// Config holds all configuration options for the scanner
type Config struct {
	Timeout         time.Duration
	Threads         int
	VerifySSL       bool
	FollowRedirects bool
	SafeCheck       bool
	Windows         bool
	WAFBypass       bool
	WAFBypassSizeKB int
	VercelWAFBypass bool
	Verbose         bool
	Quiet           bool
	NoColor         bool
	OutputFile      string
	AllResults      bool
	CustomHeaders   map[string]string
	Paths           []string
}

// DefaultConfig returns configuration with default values
func DefaultConfig() *Config {
	return &Config{
		Timeout:         10 * time.Second,
		Threads:         10,
		VerifySSL:       false,
		FollowRedirects: true,
		SafeCheck:       false,
		Windows:         false,
		WAFBypass:       false,
		WAFBypassSizeKB: 128,
		VercelWAFBypass: false,
		Verbose:         false,
		Quiet:           false,
		NoColor:         false,
		AllResults:      false,
		CustomHeaders:   make(map[string]string),
		Paths:           []string{"/"},
	}
}

// LoadFromEnv loads configuration from environment variables
func (c *Config) LoadFromEnv() {
	if v := os.Getenv("R2S_TIMEOUT"); v != "" {
		if sec, err := strconv.Atoi(v); err == nil {
			c.Timeout = time.Duration(sec) * time.Second
		}
	}

	if v := os.Getenv("R2S_THREADS"); v != "" {
		if threads, err := strconv.Atoi(v); err == nil {
			c.Threads = threads
		}
	}

	if v := os.Getenv("R2S_VERIFY_SSL"); v != "" {
		c.VerifySSL = v == "true" || v == "1"
	}

	if v := os.Getenv("R2S_WAF_BYPASS_SIZE"); v != "" {
		if size, err := strconv.Atoi(v); err == nil {
			c.WAFBypassSizeKB = size
		}
	}
}
