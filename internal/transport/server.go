package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
)

// Server is an mTLS TCP server (Party B side).
type Server struct {
	tlsConfig  *tls.Config
	listenAddr string
	listener   net.Listener

	mu       sync.Mutex
	conn     net.Conn // single peer connection (Party A)
	handler  MessageHandler
	done     chan struct{}
	started  bool
}

// MessageHandler processes incoming messages and optionally returns a response.
type MessageHandler func(msg *Message) (*Message, error)

// NewServer creates a new mTLS server.
func NewServer(listenAddr string, tlsConfig *tls.Config) *Server {
	// Enforce mTLS: require client certificate.
	cfg := tlsConfig.Clone()
	cfg.ClientAuth = tls.RequireAndVerifyClientCert

	return &Server{
		tlsConfig:  cfg,
		listenAddr: listenAddr,
		done:       make(chan struct{}),
	}
}

// SetHandler sets the message handler for incoming messages.
func (s *Server) SetHandler(h MessageHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handler = h
}

// Start begins listening for connections.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return fmt.Errorf("server already started")
	}
	s.started = true
	s.mu.Unlock()

	listener, err := tls.Listen("tcp", s.listenAddr, s.tlsConfig)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	s.listener = listener
	slog.Info("transport server listening", "addr", s.listenAddr)

	go s.acceptLoop(ctx)
	return nil
}

// Addr returns the listener address (useful when using port 0).
func (s *Server) Addr() net.Addr {
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

func (s *Server) acceptLoop(ctx context.Context) {
	for {
		select {
		case <-s.done:
			return
		case <-ctx.Done():
			return
		default:
		}

		conn, err := s.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			slog.Error("accept error", "error", err)
			continue
		}

		slog.Info("client connected", "remote", conn.RemoteAddr())
		s.mu.Lock()
		// Close any existing connection (only one peer allowed).
		if s.conn != nil {
			s.conn.Close()
		}
		s.conn = conn
		s.mu.Unlock()

		go s.handleConn(ctx, conn)
	}
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer func() {
		conn.Close()
		s.mu.Lock()
		if s.conn == conn {
			s.conn = nil
		}
		s.mu.Unlock()
		slog.Info("client disconnected", "remote", conn.RemoteAddr())
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		default:
		}

		msg, err := ReadMessage(conn)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				slog.Warn("read error", "error", err)
			}
			return
		}

		s.mu.Lock()
		handler := s.handler
		s.mu.Unlock()

		if handler == nil {
			continue
		}

		resp, err := handler(msg)
		if err != nil {
			slog.Error("handler error", "error", err, "msgType", msg.Type)
			continue
		}

		if resp != nil {
			resp.ID = msg.ID // Preserve correlation ID.
			if err := WriteMessage(conn, resp); err != nil {
				slog.Error("write response error", "error", err)
				return
			}
		}
	}
}

// Send sends a message to the connected client.
func (s *Server) Send(msg *Message) error {
	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()

	if conn == nil {
		return fmt.Errorf("no client connected")
	}
	return WriteMessage(conn, msg)
}

// Stop shuts down the server.
func (s *Server) Stop() error {
	close(s.done)
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// IsConnected reports whether a client is currently connected.
func (s *Server) IsConnected() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn != nil
}
