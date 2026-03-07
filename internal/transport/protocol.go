package transport

import (
	"encoding/binary"
	"fmt"
	"io"
)

// MessageType identifies the type of protocol message.
type MessageType uint8

const (
	// TSS protocol messages
	MsgTSSRound    MessageType = 0x01 // TSS protocol round message
	MsgDKGRound    MessageType = 0x02 // DKG round message
	MsgReshare     MessageType = 0x03 // Resharing round message

	// Application-level messages
	MsgSignRequest  MessageType = 0x10 // Sign request from Party A to Party B
	MsgSignResponse MessageType = 0x11 // Sign response from Party B to Party A
	MsgDeriveReq    MessageType = 0x12 // Derive key request
	MsgDeriveResp   MessageType = 0x13 // Derive key response
	MsgTxStatusReq  MessageType = 0x14 // Transaction status query
	MsgTxStatusResp MessageType = 0x15 // Transaction status response
	MsgSignApproved MessageType = 0x16 // Async escalation approved (Party B → Party A)
	MsgHealthCheck  MessageType = 0x20 // Health check ping
	MsgHealthResp   MessageType = 0x21 // Health check response
)

// Message is the wire format for all protocol communication.
type Message struct {
	Type    MessageType
	ID      uint64 // correlation ID for request/response matching
	Payload []byte
}

// MaxMessageSize is the maximum allowed message size (16 MB).
const MaxMessageSize = 16 * 1024 * 1024

// Wire format:
// [1 byte type][8 bytes ID][4 bytes payload length][payload]

// WriteMessage writes a framed message to a writer.
func WriteMessage(w io.Writer, msg *Message) error {
	if len(msg.Payload) > MaxMessageSize {
		return fmt.Errorf("message too large: %d > %d", len(msg.Payload), MaxMessageSize)
	}

	header := make([]byte, 13)
	header[0] = byte(msg.Type)
	binary.BigEndian.PutUint64(header[1:9], msg.ID)
	binary.BigEndian.PutUint32(header[9:13], uint32(len(msg.Payload)))

	if _, err := w.Write(header); err != nil {
		return fmt.Errorf("write header: %w", err)
	}
	if len(msg.Payload) > 0 {
		if _, err := w.Write(msg.Payload); err != nil {
			return fmt.Errorf("write payload: %w", err)
		}
	}
	return nil
}

// ReadMessage reads a framed message from a reader.
func ReadMessage(r io.Reader) (*Message, error) {
	header := make([]byte, 13)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	msg := &Message{
		Type: MessageType(header[0]),
		ID:   binary.BigEndian.Uint64(header[1:9]),
	}

	payloadLen := binary.BigEndian.Uint32(header[9:13])
	if payloadLen > MaxMessageSize {
		return nil, fmt.Errorf("message too large: %d > %d", payloadLen, MaxMessageSize)
	}

	if payloadLen > 0 {
		msg.Payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, msg.Payload); err != nil {
			return nil, fmt.Errorf("read payload: %w", err)
		}
	}
	return msg, nil
}

// SignRequestPayload is the JSON payload for MsgSignRequest.
type SignRequestPayload struct {
	To             []string `json:"to"`
	Value          string   `json:"value,omitempty"`
	Data           string   `json:"data,omitempty"` // hex calldata
	DerivationPath string   `json:"derivationPath"`
	UnsignedTx     string   `json:"unsignedTx"`     // base64 raw unsigned tx
	SignableBytes  string   `json:"signableBytes"`   // base64 hash/bytes to sign (both parties must agree)
}

// SignResponsePayload is the JSON payload for MsgSignResponse.
type SignResponsePayload struct {
	Decision string `json:"decision"` // "approve", "reject", "escalate"
	Reason   string `json:"reason"`
	TxID     string `json:"txId,omitempty"` // set if escalated
}

// SignApprovedPayload is sent by Party B to Party A when an escalated tx is approved via Telegram.
// This triggers Party A to start its side of the TSS signing protocol.
type SignApprovedPayload struct {
	TxID           string `json:"txId"`
	DerivationPath string `json:"derivationPath"`
}

// TxStatusResponsePayload is the JSON payload for MsgTxStatusResp.
type TxStatusResponsePayload struct {
	TxID     string `json:"txId"`
	Status   string `json:"status"`   // "pending", "signed", "rejected"
	Reason   string `json:"reason,omitempty"`
	SignedTx string `json:"signedTx,omitempty"` // base64-encoded signature
}
