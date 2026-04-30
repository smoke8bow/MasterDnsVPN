package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/BurntSushi/toml"
)

// Version information
const (
	AppName    = "MasterDnsVPN"
	AppVersion = "1.0.0"
)

// Config holds the top-level configuration loaded from the TOML file.
type Config struct {
	General  GeneralConfig  `toml:"general"`
	DNS      DNSConfig      `toml:"dns"`
	Tunnel   TunnelConfig   `toml:"tunnel"`
	Logging  LoggingConfig  `toml:"logging"`
}

// GeneralConfig contains general application settings.
type GeneralConfig struct {
	Mode       string `toml:"mode"`        // "client" or "server"
	ServerAddr string `toml:"server_addr"` // Remote server address
	ServerPort int    `toml:"server_port"` // Remote server port
	Secret     string `toml:"secret"`      // Shared secret / auth token
}

// DNSConfig contains DNS-related settings.
type DNSConfig struct {
	ListenAddr  string   `toml:"listen_addr"`  // Local DNS listen address
	ListenPort  int      `toml:"listen_port"`  // Local DNS listen port
	Upstream    []string `toml:"upstream"`     // Upstream DNS servers
	FakeDomain  string   `toml:"fake_domain"`  // Domain used for DNS tunneling
}

// TunnelConfig contains VPN tunnel settings.
type TunnelConfig struct {
	MTU        int    `toml:"mtu"`         // MTU for the tunnel interface
	LocalIP    string `toml:"local_ip"`    // Local tunnel IP
	RemoteIP   string `toml:"remote_ip"`   // Remote tunnel IP
	Subnet     string `toml:"subnet"`      // Tunnel subnet
}

// LoggingConfig contains logging settings.
type LoggingConfig struct {
	Level  string `toml:"level"`   // Log level: debug, info, warn, error
	Output string `toml:"output"`  // Log output: stdout or file path
}

func main() {
	// Parse command-line flags
	configPath := flag.String("config", "client_config.toml", "Path to configuration file")
	showVersion := flag.Bool("version", false, "Print version information and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("%s v%s\n", AppName, AppVersion)
		os.Exit(0)
	}

	log.Printf("Starting %s v%s", AppName, AppVersion)

	// Load configuration
	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration from %s: %v", *configPath, err)
	}

	log.Printf("Configuration loaded: mode=%s, server=%s:%d",
		cfg.General.Mode, cfg.General.ServerAddr, cfg.General.ServerPort)

	// Set up graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Start the appropriate mode
	doneCh := make(chan error, 1)
	switch cfg.General.Mode {
	case "client":
		go func() {
			doneCh <- runClient(cfg)
		}()
	case "server":
		go func() {
			doneCh <- runServer(cfg)
		}()
	default:
		log.Fatalf("Unknown mode %q: must be 'client' or 'server'", cfg.General.Mode)
	}

	// Wait for signal or completion
	select {
	case sig := <-sigCh:
		log.Printf("Received signal %v, shutting down...", sig)
	case err := <-doneCh:
		if err != nil {
			log.Fatalf("Fatal error: %v", err)
		}
	}

	log.Println("Shutdown complete.")
}

// loadConfig reads and parses the TOML configuration file.
func loadConfig(path string) (*Config, error) {
	var cfg Config
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return nil, fmt.Errorf("decode TOML: %w", err)
	}
	return &cfg, nil
}

// runClient initialises and starts the DNS-VPN client.
func runClient(cfg *Config) error {
	log.Printf("Client mode: connecting to %s:%d via DNS tunnel domain %s",
		cfg.General.ServerAddr, cfg.General.ServerPort, cfg.DNS.FakeDomain)
	// TODO: implement client logic
	select {} // block until killed
}

// runServer initialises and starts the DNS-VPN server.
func runServer(cfg *Config) error {
	log.Printf("Server mode: listening on DNS port %d, tunnel subnet %s",
		cfg.DNS.ListenPort, cfg.Tunnel.Subnet)
	// TODO: implement server logic
	select {} // block until killed
}
