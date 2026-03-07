package main

import (
	"context"
	"encoding/base64"
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

	// Wire up callbacks: when Party B starts signing, create a ServerRouter.
	svc.SetSigningStartedCallback(func(txID string, req transport.SignRequestPayload) *transport.ServerRouter {
		logger.Info("creating TSS router for signing", "txID", txID)
		return transport.NewServerRouter(server)
	})

	// Wire up callback: when escalated tx is approved, push MsgSignApproved to Party A.
	svc.SetEscalationApprovedCallback(func(txID string, derivationPath string) {
		payload, _ := json.Marshal(transport.SignApprovedPayload{
			TxID:           txID,
			DerivationPath: derivationPath,
		})
		if err := server.Send(&transport.Message{
			Type:    transport.MsgSignApproved,
			Payload: payload,
		}); err != nil {
			logger.Error("failed to push sign-approved to Party A", "txID", txID, "err", err)
		}
	})

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

		case transport.MsgTSSRound:
			// Route TSS round messages to the active signing session.
			svc.HandleTSSRound(tss.PartyID{ID: "party-a", Index: 0}, msg.Payload)
			return nil, nil // no response for TSS rounds

		case transport.MsgHealthCheck:
			return &transport.Message{
				Type:    transport.MsgHealthResp,
				ID:      msg.ID,
				Payload: []byte(`{"status":"ok"}`),
			}, nil

		case transport.MsgDeriveReq:
			var deriveReq struct {
				DerivationPath string `json:"derivationPath"`
			}
			if err := json.Unmarshal(msg.Payload, &deriveReq); err != nil {
				return nil, fmt.Errorf("unmarshal derive request: %w", err)
			}

			if err := svc.HandleDeriveRequest(ctx, deriveReq.DerivationPath); err != nil {
				logger.Error("derive failed", "path", deriveReq.DerivationPath, "error", err)
				errResp, _ := json.Marshal(map[string]string{"status": "error", "error": err.Error()})
				return &transport.Message{
					Type:    transport.MsgDeriveResp,
					ID:      msg.ID,
					Payload: errResp,
				}, nil
			}

			return &transport.Message{
				Type:    transport.MsgDeriveResp,
				ID:      msg.ID,
				Payload: []byte(`{"status":"ok"}`),
			}, nil

		case transport.MsgTxStatusReq:
			var statusReq struct {
				TxID string `json:"txId"`
			}
			if err := json.Unmarshal(msg.Payload, &statusReq); err != nil {
				return nil, fmt.Errorf("unmarshal tx status request: %w", err)
			}

			txRecord, err := svc.GetTxStatus(ctx, statusReq.TxID)
			if err != nil {
				errResp, _ := json.Marshal(transport.TxStatusResponsePayload{
					TxID:   statusReq.TxID,
					Status: "unknown",
				})
				return &transport.Message{
					Type:    transport.MsgTxStatusResp,
					ID:      msg.ID,
					Payload: errResp,
				}, nil
			}

			resp := transport.TxStatusResponsePayload{
				TxID:   txRecord.ID,
				Status: string(txRecord.Status),
				Reason: txRecord.Reason,
			}
			if txRecord.SignedTx != nil {
				resp.SignedTx = base64.StdEncoding.EncodeToString(txRecord.SignedTx)
			}
			respBytes, _ := json.Marshal(resp)
			return &transport.Message{
				Type:    transport.MsgTxStatusResp,
				ID:      msg.ID,
				Payload: respBytes,
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
