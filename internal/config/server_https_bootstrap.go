package config

import "strings"

// MainWebUIUsesHTTPS determines whether the main Web UI listens over HTTPS (consistent with the preconditions of internal/app.prepareMainServerTLS).
func MainWebUIUsesHTTPS(s *ServerConfig) bool {
	if s == nil {
		return false
	}
	if s.TLSEnabled {
		return true
	}
	if s.TLSAutoSelfSign {
		return true
	}
	cert := strings.TrimSpace(s.TLSCertPath)
	key := strings.TrimSpace(s.TLSKeyPath)
	return cert != "" && key != ""
}

// ServerHTTPRedirectEnabled whether plaintext HTTP requests are redirected to HTTPS when HTTPS is enabled on the main server (enabled by default).
func ServerHTTPRedirectEnabled(s *ServerConfig) bool {
	if s == nil || !MainWebUIUsesHTTPS(s) {
		return false
	}
	if s.TLSHTTPRedirect == nil {
		return true
	}
	return *s.TLSHTTPRedirect
}

// ApplyDevHTTPSBootstrap is used by --https / one-click scripts: forces main server TLS on.
// if tls_cert_path and tls_key_path are configured, only the PEM files are used and no self-signed cert is enabled; otherwise tls_auto_self_sign is enabled (in-memory cert, local testing only).
func ApplyDevHTTPSBootstrap(cfg *Config) {
	if cfg == nil {
		return
	}
	cfg.Server.TLSEnabled = true
	cert := strings.TrimSpace(cfg.Server.TLSCertPath)
	key := strings.TrimSpace(cfg.Server.TLSKeyPath)
	if cert != "" && key != "" {
		cfg.Server.TLSAutoSelfSign = false
		return
	}
	cfg.Server.TLSAutoSelfSign = true
}

// ApplyPlainHTTPBootstrap is used by --http / one-click scripts: forces the main server to use plaintext HTTP.
// it overrides the TLS switch, self-signed certificate and certificate paths in the config file, so that --http is not re-enabled by the HTTPS options in the config.
func ApplyPlainHTTPBootstrap(cfg *Config) {
	if cfg == nil {
		return
	}
	cfg.Server.TLSEnabled = false
	cfg.Server.TLSAutoSelfSign = false
	cfg.Server.TLSCertPath = ""
	cfg.Server.TLSKeyPath = ""
	disabled := false
	cfg.Server.TLSHTTPRedirect = &disabled
}
