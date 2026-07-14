package api

import (
	"net/http"

	"github.com/reloadlife/wireguardd/internal/crypto"
	pkgapi "github.com/reloadlife/wireguardd/pkg/api"
)

func (s *Server) handleKeysGenerate(w http.ResponseWriter, r *http.Request) {
	var req pkgapi.KeyGenerateRequest
	if err := decodeJSON(r, &req); err != nil {
		// default keypair if empty body
		req.Type = "keypair"
	}
	if req.Type == "" {
		req.Type = "keypair"
	}
	switch req.Type {
	case "keypair":
		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "keygen_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, pkgapi.KeyGenerateResponse{
			PrivateKey: kp.PrivateKey,
			PublicKey:  kp.PublicKey,
		})
	case "preshared", "psk":
		psk, err := crypto.GeneratePSK()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "keygen_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, pkgapi.KeyGenerateResponse{PresharedKey: psk})
	default:
		writeError(w, http.StatusBadRequest, "invalid_type", "type must be keypair or preshared")
	}
}
