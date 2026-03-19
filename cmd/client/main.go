// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"masterdnsvpn-go/internal/client"
)

func exitWithStderrf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format, args...)
	os.Exit(1)
}

func enabledClientListenerCount(appCfg clientConfigView) int {
	count := 0
	if appCfg.localDNSEnabled {
		count++
	}
	if appCfg.localSOCKS5Enabled {
		count++
	}
	if appCfg.protocolType == "TCP" {
		count++
	}
	return count
}

func startClientListener(wg *sync.WaitGroup, errCh chan<- error, stop context.CancelFunc, label string, runCtx context.Context, run func(context.Context) error) {
	if wg == nil || run == nil {
		return
	}
	wg.Go(func() {
		if err := run(runCtx); err != nil {
			select {
			case errCh <- fmt.Errorf("%s failed: %w", label, err):
			default:
			}
			stop()
		}
	})
}

type clientConfigView struct {
	protocolType       string
	localDNSEnabled    bool
	localSOCKS5Enabled bool
}

func main() {
	app, err := client.Bootstrap("client_config.toml")
	if err != nil {
		exitWithStderrf("Client startup failed: %v\n", err)
	}

	cfg := app.Config()
	log := app.Logger()
	log.Infof("\U0001F680 <green>Client Configuration Loaded</green>")
	log.Infof(
		"\U0001F680 <green>Client Mode</green> <magenta>|</magenta> <blue>Protocol</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Encryption</blue>: <magenta>%d</magenta>",
		cfg.ProtocolType,
		cfg.DataEncryptionMethod,
	)
	log.Infof(
		"\U00002696 <green>Resolver Balancing</green> <magenta>|</magenta> <blue>Strategy</blue>: <magenta>%d</magenta>",
		cfg.ResolverBalancingStrategy,
	)
	log.Infof(
		"\U0001F310 <green>Configured Domains</green> <magenta>|</magenta> <magenta>%d</magenta>",
		len(cfg.Domains),
	)
	log.Infof(
		"\U0001F4E1 <green>Loaded Resolvers</green> <magenta>|</magenta> <magenta>%d</magenta> <blue>endpoints</blue>",
		len(cfg.Resolvers),
	)
	log.Infof(
		"\U0001F9ED <green>Local DNS Listener</green> <magenta>|</magenta> <blue>Enabled</blue>: <yellow>%t</yellow> <magenta>|</magenta> <blue>Addr</blue>: <cyan>%s:%d</cyan>",
		cfg.LocalDNSEnabled,
		cfg.LocalDNSIP,
		cfg.LocalDNSPort,
	)
	log.Infof(
		"\U0001F9E6 <green>Local SOCKS5 Listener</green> <magenta>|</magenta> <blue>Enabled</blue>: <yellow>%t</yellow> <magenta>|</magenta> <blue>Addr</blue>: <cyan>%s:%d</cyan>",
		cfg.LocalSOCKS5Enabled,
		cfg.LocalSOCKS5IP,
		cfg.LocalSOCKS5Port,
	)
	log.Infof(
		"\U0001F50C <green>Local TCP Listener</green> <magenta>|</magenta> <blue>Mode</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Addr</blue>: <cyan>%s:%d</cyan>",
		cfg.ProtocolType,
		cfg.ListenIP,
		cfg.ListenPort,
	)
	log.Infof(
		"\U0001F5C2 <green>Connection Catalog</green> <magenta>|</magenta> <magenta>%d</magenta> <blue>domain-resolver pairs</blue>",
		len(app.Connections()),
	)
	log.Infof(
		"\U00002705 <green>Active Connections</green> <magenta>|</magenta> <magenta>%d</magenta>",
		app.Balancer().ValidCount(),
	)

	if err := app.RunInitialMTUTests(); err != nil {
		exitWithStderrf("Initial MTU testing failed: %v\n", err)
	}

	log.Infof(
		"📏 <green>Initial MTU Sync Completed</green> <magenta>|</magenta> <blue>Upload</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Download</blue>: <cyan>%d</cyan>",
		app.SyncedUploadMTU(),
		app.SyncedDownloadMTU(),
	)

	if err := app.InitializeSession(10); err != nil {
		exitWithStderrf("Session initialization failed: %v\n", err)
	}

	log.Infof(
		"\U0001F91D <green>Session Established</green> <magenta>|</magenta> <blue>ID</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Cookie</blue>: <magenta>%d</magenta>",
		app.SessionID(),
		app.SessionCookie(),
	)
	log.Infof("\U0001F3AF <green>Client Bootstrap Ready</green>")

	if !cfg.LocalDNSEnabled && !cfg.LocalSOCKS5Enabled && cfg.ProtocolType != "TCP" {
		return
	}

	runCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	enabledListeners := enabledClientListenerCount(clientConfigView{
		protocolType:       cfg.ProtocolType,
		localDNSEnabled:    cfg.LocalDNSEnabled,
		localSOCKS5Enabled: cfg.LocalSOCKS5Enabled,
	})
	errCh := make(chan error, enabledListeners)
	var listenersWG sync.WaitGroup

	if cfg.LocalDNSEnabled {
		startClientListener(&listenersWG, errCh, stop, "local dns listener", runCtx, app.RunLocalDNSListener)
	}
	if cfg.LocalSOCKS5Enabled {
		startClientListener(&listenersWG, errCh, stop, "local socks5 listener", runCtx, app.RunLocalSOCKS5Listener)
	}
	if cfg.ProtocolType == "TCP" {
		startClientListener(&listenersWG, errCh, stop, "local tcp listener", runCtx, app.RunLocalTCPListener)
	}

	listenersWG.Wait()
	select {
	case err := <-errCh:
		exitWithStderrf("%v\n", err)
	default:
	}
}
