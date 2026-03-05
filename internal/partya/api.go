package partya

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// NewRouter creates the chi router with all Party A REST endpoints.
func NewRouter(svc *Service) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.SetHeader("Content-Type", "application/json"))

	api := &apiHandler{svc: svc}

	r.Post("/derive", api.handleDerive)
	r.Post("/sign", api.handleSign)
	r.Get("/sign/{txId}", api.handleGetSignStatus)
	r.Get("/keys", api.handleListKeys)
	r.Put("/keys/{path}/label", api.handleUpdateLabel)
	r.Get("/health", api.handleHealth)

	return r
}

type apiHandler struct {
	svc *Service
}

type deriveRequest struct {
	DerivationPath string `json:"derivationPath"`
	Label          string `json:"label"`
}

func (h *apiHandler) handleDerive(w http.ResponseWriter, r *http.Request) {
	var req deriveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.DerivationPath == "" {
		writeError(w, http.StatusBadRequest, "derivationPath is required")
		return
	}

	result, err := h.svc.Derive(r.Context(), req.DerivationPath, req.Label)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}

type signAPIRequest struct {
	DerivationPath string   `json:"derivationPath"`
	To             []string `json:"to"`
	Value          string   `json:"value,omitempty"`
	Data           string   `json:"data,omitempty"` // hex-encoded
	ChainID        string   `json:"chainId,omitempty"`
	GasLimit       uint64   `json:"gasLimit,omitempty"`
	GasPrice       string   `json:"gasPrice,omitempty"`
	Nonce          uint64   `json:"nonce,omitempty"`
}

func (h *apiHandler) handleSign(w http.ResponseWriter, r *http.Request) {
	var req signAPIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.DerivationPath == "" || len(req.To) == 0 {
		writeError(w, http.StatusBadRequest, "derivationPath and to are required")
		return
	}

	var data []byte
	if req.Data != "" {
		// Strip 0x prefix if present
		hexData := req.Data
		if len(hexData) >= 2 && hexData[:2] == "0x" {
			hexData = hexData[2:]
		}
		var err error
		data, err = hexDecode(hexData)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid hex data")
			return
		}
	}

	result, err := h.svc.Sign(r.Context(), &SignRequest{
		DerivationPath: req.DerivationPath,
		To:             req.To,
		Value:          req.Value,
		Data:           data,
		ChainID:        req.ChainID,
		GasLimit:       req.GasLimit,
		GasPrice:       req.GasPrice,
		Nonce:          req.Nonce,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	status := http.StatusOK
	if result.Status == "pending_review" {
		status = http.StatusAccepted
	}
	writeJSON(w, status, result)
}

func (h *apiHandler) handleGetSignStatus(w http.ResponseWriter, r *http.Request) {
	txID := chi.URLParam(r, "txId")
	if txID == "" {
		writeError(w, http.StatusBadRequest, "txId is required")
		return
	}

	result, err := h.svc.GetSignStatus(r.Context(), txID)
	if err != nil {
		writeError(w, http.StatusNotFound, "transaction not found")
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func (h *apiHandler) handleListKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := h.svc.ListKeys(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	keysMap := make(map[string]KeyInfo, len(keys))
	for _, k := range keys {
		keysMap[k.DerivationPath] = k
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"keys": keysMap})
}

type updateLabelRequest struct {
	Label string `json:"label"`
}

func (h *apiHandler) handleUpdateLabel(w http.ResponseWriter, r *http.Request) {
	path := chi.URLParam(r, "path")
	if path == "" {
		writeError(w, http.StatusBadRequest, "path is required")
		return
	}

	var req updateLabelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.svc.store.UpdateLabel(r.Context(), path, req.Label); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *apiHandler) handleHealth(w http.ResponseWriter, r *http.Request) {
	health := h.svc.Health(r.Context())
	status := http.StatusOK
	if health.Status != "ok" {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, health)
}

// Helper functions

type apiError struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(apiError{Error: msg})
}

func hexDecode(s string) ([]byte, error) {
	b := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		high := hexVal(s[i])
		low := hexVal(s[i+1])
		if high == 0xFF || low == 0xFF {
			return nil, &json.InvalidUnmarshalError{}
		}
		b[i/2] = high<<4 | low
	}
	return b, nil
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	default:
		return 0xFF
	}
}
