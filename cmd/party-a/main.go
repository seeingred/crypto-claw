package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/seeingred/crypto-claw/internal/config"
	"github.com/seeingred/crypto-claw/internal/partya"
	"github.com/seeingred/crypto-claw/internal/store"
	"github.com/seeingred/crypto-claw/internal/transport"
	"github.com/seeingred/crypto-claw/internal/tss"
	"github.com/seeingred/crypto-claw/internal/vm"
	"github.com/seeingred/crypto-claw/internal/vm/evm"
	"github.com/seeingred/crypto-claw/internal/vm/solana"
	"github.com/seeingred/crypto-claw/internal/vm/tendermint"
)

func main() {
	configPath := flag.String("config", "config.json", "path to configuration file")
	passphrase := flag.String("passphrase", "", "encryption passphrase for key shares")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}
	if cfg.Party != "a" {
		fmt.Fprintf(os.Stderr, "config party must be 'a', got '%s'\n", cfg.Party)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize store.
	st, err := store.NewPostgresStore(ctx, cfg.Database.DSN(), *passphrase)
	if err != nil {
		log.Fatalf("failed to init store: %v", err)
	}
	defer st.Close()

	// Initialize mTLS transport client to Party B.
	tlsCfg, err := transport.LoadCerts(cfg.Transport.CertFile, cfg.Transport.KeyFile, cfg.Transport.CACertFile)
	if err != nil {
		log.Fatalf("failed to load TLS certs: %v", err)
	}
	client := transport.NewClient(cfg.Transport.RemoteAddr, tlsCfg)
	if err := client.Connect(ctx); err != nil {
		log.Fatalf("failed to connect to Party B: %v", err)
	}
	defer client.Close()

	// Initialize TSS protocol.
	proto := tss.NewProtocol(0) // 2-of-2 threshold

	// Initialize VM adapter registry.
	// All adapters are always registered — chain config provides RPC URLs, not adapter enablement.
	registry := vm.NewRegistry()
	registry.Register([]string{"60"}, evm.New())
	registry.Register([]string{"501"}, solana.New())

	// Use config prefix/denom if available, otherwise defaults.
	tmPrefix, tmDenom := "", ""
	if len(cfg.Chains.Tendermint) > 0 {
		tmPrefix = cfg.Chains.Tendermint[0].Prefix
		tmDenom = cfg.Chains.Tendermint[0].Denom
	}
	registry.Register([]string{"118"}, tendermint.New(tmPrefix, tmDenom))

	// Create transport adapter.
	tc := &transportAdapter{client: client}

	// Initialize service with transport client as TSS router.
	svc := partya.NewService(st, tc, client, proto, registry)

	// Handle incoming push messages from Party B (MsgSignApproved).
	client.SetHandler(func(msg *transport.Message) (*transport.Message, error) {
		switch msg.Type {
		case transport.MsgSignApproved:
			var payload transport.SignApprovedPayload
			if err := json.Unmarshal(msg.Payload, &payload); err != nil {
				slog.Error("unmarshal sign-approved", "err", err)
				return nil, nil
			}
			slog.Info("received sign-approved from Party B", "txID", payload.TxID)
			// Run signing in a goroutine so the readLoop isn't blocked.
			go svc.HandleSignApproved(context.Background(), payload.TxID, payload.DerivationPath)
			return nil, nil
		default:
			slog.Warn("unhandled push message", "type", msg.Type)
			return nil, nil
		}
	})

	// Start HTTP server.
	router := partya.NewRouter(svc)
	server := &http.Server{
		Addr:    cfg.API.ListenAddr,
		Handler: router,
	}

	go func() {
		slog.Info("Party A API listening", "addr", cfg.API.ListenAddr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// Wait for shutdown signal.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	slog.Info("shutting down Party A")
	cancel()
	server.Shutdown(context.Background())
}

// transportAdapter wraps transport.Client to satisfy partya.TransportClient.
type transportAdapter struct {
	client *transport.Client
}

func (t *transportAdapter) Send(ctx context.Context, msg *transport.Message) error {
	return t.client.SendMessage(msg)
}

func (t *transportAdapter) SendAndReceive(ctx context.Context, msg *transport.Message) (*transport.Message, error) {
	return t.client.Request(ctx, msg)
}

func (t *transportAdapter) Close() error {
	return t.client.Close()
}
