// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/logger"
	"masterdnsvpn-go/internal/security"
	UDPServer "masterdnsvpn-go/internal/udpserver"
)

func main() {
	cfg, err := config.LoadServerConfig("server_config.toml")
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Server startup failed: %v\n", err)
		os.Exit(1)
	}

	log := logger.New("MasterDnsVPN Server", cfg.LogLevel)
	keyInfo, err := security.EnsureServerEncryptionKey(cfg)
	if err != nil {
		log.Errorf("❌ <red>Encryption Key Setup Failed</red> <magenta>|</magenta> <cyan>%v</cyan>", err)
		os.Exit(1)
	}

	codec, err := security.NewCodecFromConfig(cfg, keyInfo.Key)
	if err != nil {
		log.Errorf("❌ <red>Encryption Codec Setup Failed</red> <magenta>|</magenta> <cyan>%v</cyan>", err)
		os.Exit(1)
	}

	srv := UDPServer.New(cfg, log, codec)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Infof("🚀 <green>Server Configuration Loaded</green>")
	log.Infof(
		"🛰️ <green>Listener</green> <magenta>|</magenta> <green>Addr: </green><cyan>%s</cyan> <magenta>|</magenta> <green>Readers:</green> <cyan>%d</cyan> <magenta>|</magenta> <green>Workers:</green> <cyan>%d</cyan>",
		cfg.Address(),
		cfg.UDPReaders,
		cfg.DNSRequestWorkers,
	)

	if len(cfg.Domain) > 0 {
		log.Infof(
			"🌐 <green>Allowed Domains</green> <magenta>|</magenta> <cyan>%s</cyan> <magenta>|</magenta> <green>Min Label:</green> <cyan>%d</cyan>",
			strings.Join(cfg.Domain, ", "),
			cfg.MinVPNLabelLength,
		)
	} else {
		log.Warnf(
			"⚠️ <yellow>No Allowed Domains Configured</yellow> <magenta>|</magenta> <blue>Fallback</blue>: <green>NODATA</green>",
		)
	}
	log.Infof(
		"🔐 <green>Encryption</green> <magenta>|</magenta> <green>Method:</green> <cyan>%s</cyan> <gray>(id=%d)</gray>",
		keyInfo.MethodName,
		keyInfo.MethodID,
	)
	if keyInfo.Generated {
		log.Warnf(
			"🗝️ <yellow>Encryption Key Generated</yellow> <magenta>|</magenta> <blue>Path</blue>: <cyan>%s</cyan>",
			keyInfo.Path,
		)
	} else {
		log.Infof(
			"🗂️ <green>Encryption Key Loaded</green> <magenta>|</magenta> <blue>Path</blue>: <cyan>%s</cyan>",
			keyInfo.Path,
		)
	}
	log.Infof("🔑 <green>Active Encryption Key</green> <magenta>|</magenta> <yellow>%s</yellow>", keyInfo.Key)
	log.Infof("▶️ <green>Starting UDP Server</green> <magenta>|</magenta> <blue>Addr</blue>: <cyan>%s</cyan>", cfg.Address())

	if err := srv.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Errorf("💥 <red>Server Stopped Unexpectedly</red> <magenta>|</magenta> <cyan>%v</cyan>", err)
		os.Exit(1)
	}

	log.Infof("🛑 <yellow>Server Stopped</yellow>")
}
