package tsm

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"gitlab.com/sepior/go-tsm-sdkv2/internal/pki"
	"gitlab.com/sepior/go-tsm-sdkv2/internal/crypto/ed448"
	"gitlab.com/sepior/go-tsm-sdkv2/ec"
	"io"
	"net/http"
	"regexp"
)

func pkixPublicKeyToPoint(pkixPublicKey []byte) (ec.Point, error) {
	cryptoPublicKey, err := pki.ParsePublicKey(pkixPublicKey)
	if err != nil {
		return ec.Point{}, err
	}

	switch publicKey := cryptoPublicKey.(type) {
	case *ecdsa.PublicKey:
		return ec.NewPointFromECPublicKey(publicKey)
	case ed25519.PublicKey:
		return ec.Edwards25519.DecodePoint(publicKey, true)
	case ed448.PublicKey:
		return ec.Edwards448.DecodePoint(publicKey, true)
	default:
		return ec.Point{}, fmt.Errorf("unsupported public key")
	}
}

func pointToPKIXPublicKey(p ec.Point) ([]byte, error) {
	// This will also catch sepc256k1 which is used for both ECDSA and BIP-340.
	if p.Curve().SupportsECDSA() {
		ecPublicKey, err := p.ECPublicKey()
		if err != nil {
			return nil, err
		}
		return pki.MarshalPublicKey(ecPublicKey)
	}

	switch p.Curve().Name() {
	case ec.Edwards25519.Name():
		return pki.MarshalPublicKey(ed25519.PublicKey(p.Encode()))
	case ec.Edwards448.Name():
		return pki.MarshalPublicKey(ed448.PublicKey(p.Encode()))
	default:
		return nil, fmt.Errorf("unsupported public key")
	}
}

func marshalJSON(val interface{}) (io.Reader, error) {
	buf, err := json.Marshal(val)
	if err != nil {
		return nil, toTSMError(fmt.Errorf("error creating JSON: %w", err), ErrOperationFailed)
	}

	return bytes.NewReader(buf), nil
}

func unmarshalJSON(reader io.Reader, val interface{}) error {
	err := json.NewDecoder(reader).Decode(val)
	if err != nil {
		return toTSMError(fmt.Errorf("error parsing JSON: %w", err), ErrOperationFailed)
	}
	return nil
}

func closeResponseBody(response *http.Response) {
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
}

var allowedCharsInKeyID = regexp.MustCompile(`^[a-zA-Z0-9_\-]+$`).MatchString

func validateKeyID(keyID string) error {
	if keyID == "" {
		return fmt.Errorf("key ID is empty")
	}
	if len(keyID) > 28 {
		return fmt.Errorf("key ID must not be longer than 28 characters, but it was %d", len(keyID))
	}
	if !allowedCharsInKeyID(keyID) {
		return fmt.Errorf("key ID contains invalid characters: %s", keyID)
	}
	return nil
}
