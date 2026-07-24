package crypto

import (
	"fmt"

	"github.com/advanced-wg/awgctrl-go/wgtypes"
)

// KeyPair is a WireGuard private/public key pair (base64-encoded).
type KeyPair struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

// GenerateKeyPair creates a new Curve25519 key pair.
func GenerateKeyPair() (KeyPair, error) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return KeyPair{}, fmt.Errorf("generate private key: %w", err)
	}
	return KeyPair{
		PrivateKey: key.String(),
		PublicKey:  key.PublicKey().String(),
	}, nil
}

// GeneratePSK creates a new preshared key.
func GeneratePSK() (string, error) {
	key, err := wgtypes.GenerateKey()
	if err != nil {
		return "", fmt.Errorf("generate psk: %w", err)
	}
	return key.String(), nil
}

// PublicFromPrivate derives the public key from a base64 private key.
func PublicFromPrivate(privateKey string) (string, error) {
	key, err := wgtypes.ParseKey(privateKey)
	if err != nil {
		return "", fmt.Errorf("parse private key: %w", err)
	}
	return key.PublicKey().String(), nil
}

// ParseKey validates a WireGuard key string.
func ParseKey(s string) (wgtypes.Key, error) {
	return wgtypes.ParseKey(s)
}
