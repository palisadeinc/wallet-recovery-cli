package tsm

import (
	"context"
	"fmt"
	"net/http"
)

// KeyManagementAPI provides general functions for management of keys in the TSM.
//
// These operations do not run any MPC session, and only affect the state of the current player. So, for example,
// to fully delete presignatures for a key, DeletePresignatures() must be called on all players.
type KeyManagementAPI interface {

	// ListKeys returns a list of IDs for all keys accessible by the application.
	ListKeys(ctx context.Context) (keyIDs []string, err error)

	// DeleteKeyShare deletes the player's share of a key.
	DeleteKeyShare(ctx context.Context, keyID string) (err error)

	// DeletePresignatures deletes all the player's presignature shares for a key.
	DeletePresignatures(ctx context.Context, keyID string) (err error)

	// CountPresignatures returns a count of the presignatures available for a key.
	CountPresignatures(ctx context.Context, keyID string) (presigCount int, err error)
}

type keyManagementService struct {
	*node
}

func (k *keyManagementService) ListKeys(ctx context.Context) (keyIDs []string, err error) {
	response, err := k.call(ctx, http.MethodPost, "/key/keys/self", &SessionConfig{}, k.sendAuthenticatedRequest, func() interface{} {
		return struct{}{}
	})
	if err != nil {
		return nil, toTSMError(err, ErrOperationFailed)
	}

	var jsonResponse []struct {
		KeyID string `json:"key_id"`
	}

	err = unmarshalJSON(response, &jsonResponse)
	if err != nil {
		return nil, toTSMError(err, ErrOperationFailed)
	}

	outKeyIDs := make([]string, len(jsonResponse))
	for i := range jsonResponse {
		outKeyIDs[i] = jsonResponse[i].KeyID
	}

	return outKeyIDs, nil
}

func (k *keyManagementService) DeleteKeyShare(ctx context.Context, keyID string) (err error) {
	if err = validateKeyID(keyID); err != nil {
		return toTSMError(err, ErrInvalidInput)
	}

	_, err = k.call(ctx, http.MethodDelete, fmt.Sprintf("/key/%s", keyID), &SessionConfig{}, k.sendAuthenticatedRequest, nil)
	if err != nil {
		return toTSMError(err, ErrOperationFailed)
	}

	return nil
}

func (k *keyManagementService) DeletePresignatures(ctx context.Context, keyID string) (err error) {
	if err = validateKeyID(keyID); err != nil {
		return toTSMError(err, ErrInvalidInput)
	}

	_, err = k.call(ctx, http.MethodDelete, fmt.Sprintf("/key/%s/presigs", keyID), &SessionConfig{}, k.sendAuthenticatedRequest, nil)
	if err != nil {
		return toTSMError(err, ErrOperationFailed)
	}

	return nil
}

func (k *keyManagementService) CountPresignatures(ctx context.Context, keyID string) (presigCount int, err error) {
	response, err := k.call(ctx, http.MethodPost, fmt.Sprintf("/key/%s/count/presigs", keyID), &SessionConfig{}, k.sendAuthenticatedRequest, func() interface{} {
		return struct{}{}
	})
	if err != nil {
		return 0, toTSMError(err, ErrOperationFailed)
	}

	err = unmarshalJSON(response, &presigCount)
	if err != nil {
		return 0, toTSMError(err, ErrOperationFailed)
	}

	return presigCount, nil
}
