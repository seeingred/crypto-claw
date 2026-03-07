package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/seeingred/crypto-claw/internal/tss"
)

// Client is an mTLS TCP client (Party A side).
type Client struct {
	remoteAddr string
	tlsConfig  *tls.Config

	mu       sync.Mutex
	conn     net.Conn
	done     chan struct{}
	msgIDSeq atomic.Uint64

	// Reconnection settings.
	maxBackoff    time.Duration
	initialDelay  time.Duration

	// Message routing for TSS protocol.
	incomingCh chan tss.IncomingMessage
	handler    MessageHandler

	// Pending response channels for request/reply.
	pending   map[uint64]chan *Message
	pendingMu sync.Mutex
	writeMu   sync.Mutex // protects concurrent writes to conn
}

// NewClient creates a new mTLS client.
func NewClient(remoteAddr string, tlsConfig *tls.Config) *Client {
	cfg := tlsConfig.Clone()
	cfg.ClientAuth = tls.NoClientCert // Client side: server verifies us via our cert.

	return &Client{
		remoteAddr:   remoteAddr,
		tlsConfig:    cfg,
		done:         make(chan struct{}),
		maxBackoff:   30 * time.Second,
		initialDelay: 500 * time.Millisecond,
		incomingCh:   make(chan tss.IncomingMessage, 100),
		pending:      make(map[uint64]chan *Message),
	}
}

// SetHandler sets the handler for incoming messages that aren't responses to requests.
func (c *Client) SetHandler(h MessageHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.handler = h
}

// Connect establishes a connection to the server with reconnection.
func (c *Client) Connect(ctx context.Context) error {
	return c.connectWithRetry(ctx)
}

func (c *Client) connectWithRetry(ctx context.Context) error {
	delay := c.initialDelay

	for attempt := 0; ; attempt++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.done:
			return fmt.Errorf("client closed")
		default:
		}

		conn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: 10 * time.Second},
			"tcp",
			c.remoteAddr,
			c.tlsConfig,
		)
		if err != nil {
			slog.Warn("connect failed, retrying", "addr", c.remoteAddr, "attempt", attempt, "error", err)

			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return ctx.Err()
			case <-c.done:
				return fmt.Errorf("client closed")
			}

			delay = time.Duration(math.Min(float64(delay)*2, float64(c.maxBackoff)))
			continue
		}

		slog.Info("connected to server", "addr", c.remoteAddr)
		c.mu.Lock()
		c.conn = conn
		c.mu.Unlock()

		go c.readLoop(ctx, conn)
		return nil
	}
}

func (c *Client) readLoop(ctx context.Context, conn net.Conn) {
	defer func() {
		c.mu.Lock()
		if c.conn == conn {
			c.conn = nil
		}
		c.mu.Unlock()

		// Attempt reconnection.
		go func() {
			select {
			case <-c.done:
				return
			default:
				if err := c.connectWithRetry(ctx); err != nil {
					slog.Error("reconnection failed", "error", err)
				}
			}
		}()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return
		default:
		}

		msg, err := ReadMessage(conn)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				slog.Warn("read error, will reconnect", "error", err)
			}
			return
		}

		// Check if this is a response to a pending request.
		c.pendingMu.Lock()
		ch, ok := c.pending[msg.ID]
		if ok {
			delete(c.pending, msg.ID)
		}
		c.pendingMu.Unlock()

		if ok {
			ch <- msg
			continue
		}

		// Handle as TSS protocol message or pass to handler.
		switch msg.Type {
		case MsgTSSRound, MsgDKGRound, MsgReshare:
			// Route to TSS protocol message channel.
			select {
			case c.incomingCh <- tss.IncomingMessage{
				From:    tss.PartyID{ID: "party-b"}, // Will be parsed from payload.
				Payload: msg.Payload,
			}:
			default:
				slog.Warn("incoming TSS message channel full, dropping")
			}

		default:
			c.mu.Lock()
			handler := c.handler
			c.mu.Unlock()
			if handler != nil {
				resp, err := handler(msg)
				if err != nil {
					slog.Error("handler error", "error", err)
					continue
				}
				if resp != nil {
					resp.ID = msg.ID
					if err := c.SendMessage(resp); err != nil {
						slog.Error("send response error", "error", err)
					}
				}
			}
		}
	}
}

// SendMessage sends a message to the server.
func (c *Client) SendMessage(msg *Message) error {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()

	if conn == nil {
		return fmt.Errorf("not connected")
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return WriteMessage(conn, msg)
}

// Request sends a message and waits for a response with the same correlation ID.
func (c *Client) Request(ctx context.Context, msg *Message) (*Message, error) {
	msg.ID = c.msgIDSeq.Add(1)

	ch := make(chan *Message, 1)
	c.pendingMu.Lock()
	c.pending[msg.ID] = ch
	c.pendingMu.Unlock()

	if err := c.SendMessage(msg); err != nil {
		c.pendingMu.Lock()
		delete(c.pending, msg.ID)
		c.pendingMu.Unlock()
		return nil, err
	}

	select {
	case resp := <-ch:
		return resp, nil
	case <-ctx.Done():
		c.pendingMu.Lock()
		delete(c.pending, msg.ID)
		c.pendingMu.Unlock()
		return nil, ctx.Err()
	}
}

// Send implements tss.MessageRouter by sending TSS protocol messages over the transport.
func (c *Client) Send(ctx context.Context, to tss.PartyID, msg []byte) error {
	return c.SendMessage(&Message{
		Type:    MsgTSSRound,
		ID:      c.msgIDSeq.Add(1),
		Payload: msg,
	})
}

// Receive implements tss.MessageRouter by returning the incoming TSS message channel.
func (c *Client) Receive() <-chan tss.IncomingMessage {
	return c.incomingCh
}

// Close shuts down the client.
func (c *Client) Close() error {
	close(c.done)
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn != nil {
		return conn.Close()
	}
	return nil
}

// IsConnected reports whether the client is currently connected.
func (c *Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn != nil
}

// Ensure Client implements tss.MessageRouter.
var _ tss.MessageRouter = (*Client)(nil)
