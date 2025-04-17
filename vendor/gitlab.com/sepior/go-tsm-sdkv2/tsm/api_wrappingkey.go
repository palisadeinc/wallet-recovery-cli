package tsm

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"gitlab.com/sepior/go-tsm-sdkv2/internal/transport"
	"net/http"
	"sync"
)

// WrappingKeyAPI allows to obtain the wrapping key of a player.
//
// Each player in the TSM has its own wrapping key. The wrapping key is an RSA public key which can be used to encrypt
// data to be imported to the player.
type WrappingKeyAPI interface {

	// WrappingKey returns the wrapping key for this player, a DER encoded SubjectPublicKeyInfo RSA public key.
	WrappingKey(ctx context.Context) (wrappingKey []byte, err error)

	// Fingerprint returns the wrapping key fingerprint for this player.
	Fingerprint(ctx context.Context) (fingerPrint string, err error)
}

type wrappingKeyCache struct {
	lock        sync.Mutex
	key         []byte
	fingerprint string
}

type wrappingKeyService struct {
	*node
	cache *wrappingKeyCache
}

func (w *wrappingKeyService) WrappingKey(ctx context.Context) (wrappingKey []byte, err error) {
	wrappingKey, _, err = w.fetchWrappingKey(ctx)
	return wrappingKey, err
}

func (w *wrappingKeyService) Fingerprint(ctx context.Context) (fingerprint string, err error) {
	_, fingerprint, err = w.fetchWrappingKey(ctx)
	return fingerprint, err
}

func (w *wrappingKeyService) fetchWrappingKey(ctx context.Context) (wrappingKey []byte, fingerprint string, err error) {
	if w.cache.key != nil {
		return w.cache.key, w.cache.fingerprint, nil
	}

	w.cache.lock.Lock()
	defer w.cache.lock.Unlock()

	if w.cache.key != nil {
		return w.cache.key, w.cache.fingerprint, nil
	}

	response, err := w.call(ctx, http.MethodGet, "/wrapping/key", &SessionConfig{}, w.sendAuthenticatedRequest, nil)
	if err != nil {
		return nil, "", toTSMError(err, ErrInvalidInput)
	}

	var jsonResponse transport.WrappingKeyResponse
	err = unmarshalJSON(response, &jsonResponse)
	if err != nil {
		return nil, "", toTSMError(err, ErrOperationFailed)
	}

	_, err = x509.ParsePKIXPublicKey(jsonResponse.WrappingKey)
	if err != nil {
		return nil, "", toTSMError(fmt.Errorf("wrapping key: invalid wrapping key: %w", err), ErrOperationFailed)
	}

	h := sha256.New()
	h.Write(jsonResponse.WrappingKey)
	fingerprint = hex.EncodeToString(h.Sum(nil))

	w.cache.key = jsonResponse.WrappingKey
	w.cache.fingerprint = fingerprint

	return jsonResponse.WrappingKey, fingerprint, nil
}
