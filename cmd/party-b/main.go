package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/seeingred/crypto-claw/internal/config"
	"github.com/seeingred/crypto-claw/internal/partyb"
	"github.com/seeingred/crypto-claw/internal/store"
	"github.com/seeingred/crypto-claw/internal/transport"
	"github.com/seeingred/crypto-claw/internal/tss"
)

func main() {
	configPath := flag.String("config", "config.json", "path to configuration file")
	passphrase := flag.String("passphrase", "", "encryption passphrase for key shares")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}
	if cfg.Party != "b" {
		fmt.Fprintf(os.Stderr, "config party must be 'b', got '%s'\n", cfg.Party)
		os.Exit(1)
	}

	logger := slog.Default()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize store.
	st, err := store.NewPostgresStore(ctx, cfg.Database.DSN(), *passphrase)
	if err != nil {
		log.Fatalf("failed to init store: %v", err)
	}
	defer st.Close()

	// Initialize TSS protocol.
	proto := tss.NewProtocol(0) // 2-of-2 threshold

	// Initialize Party B service.
	svc, err := partyb.New(cfg, st, proto, logger)
	if err != nil {
		log.Fatalf("failed to init Party B service: %v", err)
	}

	// Initialize mTLS transport server.
	tlsCfg, err := transport.LoadCerts(cfg.Transport.CertFile, cfg.Transport.KeyFile, cfg.Transport.CACertFile)
	if err != nil {
		log.Fatalf("failed to load TLS certs: %v", err)
	}
	server := transport.NewServer(cfg.Transport.ListenAddr, tlsCfg)

	// Set handler for incoming messages.
	server.SetHandler(func(msg *transport.Message) (*transport.Message, error) {
		switch msg.Type {
		case transport.MsgSignRequest:
			var req transport.SignRequestPayload
			if err := json.Unmarshal(msg.Payload, &req); err != nil {
				return nil, fmt.Errorf("unmarshal sign request: %w", err)
			}

			resp := svc.HandleSignRequest(ctx, msg.ID, req)
			respBytes, err := json.Marshal(resp)
			if err != nil {
				return nil, fmt.Errorf("marshal sign response: %w", err)
			}

			return &transport.Message{
				Type:    transport.MsgSignResponse,
				ID:      msg.ID,
				Payload: respBytes,
			}, nil

		case transport.MsgHealthCheck:
			return &transport.Message{
				Type:    transport.MsgHealthResp,
				ID:      msg.ID,
				Payload: []byte(`{"status":"ok"}`),
			}, nil

		case transport.MsgDeriveReq:
			// Party B also derives the key for its share.
			logger.Info("derive request received", "payload", string(msg.Payload))
			return &transport.Message{
				Type:    transport.MsgDeriveResp,
				ID:      msg.ID,
				Payload: []byte(`{"status":"ok"}`),
			}, nil

		default:
			logger.Warn("unknown message type", "type", msg.Type)
			return nil, nil
		}
	})

	if err := server.Start(ctx); err != nil {
		log.Fatalf("failed to start transport server: %v", err)
	}

	// Start the service (Telegram bot, etc.).
	svc.Start(ctx)
	defer svc.Stop()

	slog.Info("Party B running", "addr", cfg.Transport.ListenAddr)

	// Wait for shutdown signal.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	slog.Info("shutting down Party B")
	cancel()
	server.Stop()
}
