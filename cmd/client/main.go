// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package main

import (
	"fmt"
	"os"

	"masterdnsvpn-go/internal/client"
)

func main() {
	app, err := client.Bootstrap("client_config.toml")
	if err != nil {
		_, _ = os.Stderr.WriteString(fmt.Sprintf("Client startup failed: %v\n", err))
		os.Exit(1)
	}

	cfg := app.Config()
	log := app.Logger()
	log.Infof("🚀 <green>Client Configuration Loaded</green>")
	log.Infof(
		"🧭 <green>Client Mode</green> <magenta>|</magenta> <blue>Protocol</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Encryption</blue>: <magenta>%d</magenta>",
		cfg.ProtocolType,
		cfg.DataEncryptionMethod,
	)
	log.Infof(
		"⚖️ <green>Resolver Balancing</green> <magenta>|</magenta> <blue>Strategy</blue>: <magenta>%d</magenta>",
		cfg.ResolverBalancingStrategy,
	)
	log.Infof(
		"🌐 <green>Configured Domains</green> <magenta>|</magenta> <magenta>%d</magenta>",
		len(cfg.Domains),
	)
	log.Infof(
		"📡 <green>Loaded Resolvers</green> <magenta>|</magenta> <magenta>%d</magenta> <blue>endpoints</blue>",
		len(cfg.Resolvers),
	)
	log.Infof(
		"🗂️ <green>Connection Catalog</green> <magenta>|</magenta> <magenta>%d</magenta> <blue>domain-resolver pairs</blue>",
		len(app.Connections()),
	)
	log.Infof(
		"✅ <green>Active Connections</green> <magenta>|</magenta> <magenta>%d</magenta>",
		app.Balancer().ValidCount(),
	)

	if err := app.RunInitialMTUTests(); err != nil {
		_, _ = os.Stderr.WriteString(fmt.Sprintf("Initial MTU testing failed: %v\n", err))
		os.Exit(1)
	}

	log.Infof(
		"📏 <green>Initial MTU Sync Completed</green> <magenta>|</magenta> <blue>Upload</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Download</blue>: <cyan>%d</cyan>",
		app.SyncedUploadMTU(),
		app.SyncedDownloadMTU(),
	)
	log.Infof("🎯 <green>Client Bootstrap Ready</green>")
}
