package tsm

import (
	"context"
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/transport"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/partialresults/partialsymmetric"
	"net/http"
)

type HMACWrappedKeyShare struct {
	WrappedKeyShare []byte
	Checksum        []byte
}

// HMACAPI provides functionality for generating, importing, and exporting HMAC keys, as well as the HMAC-SHA256 and
// HMAC-SHA512 operations.
type HMACAPI interface {

	// GenerateKey instructs this player to participate in an MPC session that generates an HMAC key.
	//
	// All players in the session must agree on threshold, key length, and optionally a desired key ID.
	//
	// Input:
	//   - threshold: The security threshold for the key. Must be at least 1 and at most the total number of nodes
	//     minus one. The TSM guarantees that the key remains secure as long as at most threshold number of MPC nodes
	//     are corrupted.
	//   - keyLength: The byte length of the key to generate. Must be between 1 and 256.
	//   - desiredKeyID (optional): A unique string of length 28, containing only ASCII letters and numbers. If
	//     provided, the generated key will get this key ID.
	//
	// Output:
	//   - keyID: The ID of the new key. If desiredKeyID was provided, it will be output here.
	GenerateKey(ctx context.Context, sessionConfig *SessionConfig, threshold, keyLength int, desiredKeyID string) (keyID string, err error)

	// ExportKeyShares instructs the player to participate in an MPC session that exports key shares of an HMAC key.
	//
	// The call blocks until all players are ready, meaning that this method have been called on their SDK. If this
	// does not happen within a given time frame (default 10 seconds), the session times out.
	//
	// If all players agree on the key ID, a random xor sharing of the key is generated, and one share is output to
	// each player. The output share is wrapped (encrypted) using the provided wrapping key.
	//
	// In addition to the wrapped key share, each player receives a checksum of the key. The checksum can be used
	// to validate the key's integrity, when the shares are later used to recover the key, or when they are imported
	// into a TSM.
	//
	// Export of key shares must be enabled in the MPC node configuration, and each player is configured with a
	// whitelist of wrapping keys and only accepts to export if the provided wrapping key matches the whitelist.
	//
	// Input:
	//   - keyID: The ID of an existing AES key in the TSM.
	//   - wrappingKey: The wrapping key used to encrypt the key share exported to the player. Must be provided as
	//     SubjectPublicKeyInfo in an ASN.1 DER encoding. The wrapping key of a target TSM can be obtained by
	//     WrappingKey().
	//
	// Output:
	//   - wrappedKeyShare: A wrapped xor key share and chain code exported to this player. The actual key is computed
	//     as share1 xor share2 xor share3 ... where xor is bit-wise xor.
	ExportKeyShares(ctx context.Context, sessionConfig *SessionConfig, keyID string, wrappingKey []byte) (wrappedKeyShare *HMACWrappedKeyShare, err error)

	// ImportKeyShares instructs the player to participate in an MPC session that imports key shares of an HMAC key.
	//
	// The wrapped key share is first unwrapped (decrypted) by the player, using the player's private wrapping key, and
	// the unwrapped key is provided to the MPC session, along with the threshold, checksum and desired key ID.
	//
	// The call blocks until all players are instructed to participate in the session, or the session times out
	// (default timeout is 10 seconds).
	//
	// Once all players have provided input, the thresholds provided by all players in the session are compared, and
	// the session aborts unless they are equal. Similarly, the provided checksum and optional desired key ID are
	// compared to ensure that all participating players agree on these values.
	//
	// The MPC session then starts. The MPC session first recovers the HMAC from the provided key shares.
	// If the optional checksum is provided, the session then computes the expected checksum as the first three bytes
	// of SHA-256("BuilderVault HMAC Key" || key), and then compares the provided checksum with the expected checksum.
	// If the checksum does not match the expected checksum, the MPC session aborts. Finally, a secret sharing of the
	// HMAC key is stored among the MPC nodes. The stored sharing is a new independent sharing of the key, not related
	// to the xor shares that was provided as input.
	//
	// To import from a source TSM to a target TSM, you first call WrappingKey() on each of the players in the target
	// TSM. Then call ExportKeyShares() on each of the players in the source TSM, providing the wrapping keys. The
	// output from ExportKeyShares() on the source TSM, along with the public key, obtained from PublicKey() on the
	// source TSM, can be used as input to ImportKeyShares() on the target TSM.
	//
	// If you instead want to import a private Schnorr key from somewhere else, you may want to use the helper functions
	// tsmutils.SecretShareHMAC() to split the key into shares, and tsmutils.Wrap() to wrap each share with the
	// wrapping keys obtained from calls to WrappingKey() on each of the players.
	//
	// Input:
	//   - threshold: The security threshold for the imported key.
	//   - wrappingKey: The wrapping key used to encrypt the key share exported to the player. Must be provided as
	//     SubjectPublicKeyInfo in an ASN.1 DER encoding (see RFC 5280, Section 4.1). The wrapping key of a target TSM
	//     can be obtained by WrappingKey().
	//   - wrappedKeyShare: The key share for this player, wrapped using the player's wrapping key, which can be
	//     obtained by WrappingKey().
	//   - checksum (optional): The first three bytes of SHA256("BuilderVault HMAC Key" || key)
	//   - desiredKeyID (optional): A unique string of length 28, containing only ASCII letters and numbers. If
	//     provided, the imported key will get this key ID.
	//
	// Output:
	//   - keyID: The ID of the imported key. If desiredKeyID was provided, it will be output here.
	ImportKeyShares(ctx context.Context, sessionConfig *SessionConfig, threshold int, wrappedKeyShare, checksum []byte, desiredKeyID string) (keyID string, err error)

	// HMACSHA256 instructs this player to participate in an MPC session for generating a HMAC-SHA256 digest of some
	// provided data.
	//
	// The call blocks until all players are instructed to participate in the session, or the session times out
	// (default timeout is 10 seconds). All players in the session must agree on keyID, initialization vector (iv),
	// and keyStreamLength.
	//
	// Input:
	//   - keyID: The key to use for producing the HMAC-SHA256 digest.
	//   - data: The input data to HMAC-SHA256. Must be at most 16384 bytes.
	//
	// Output:
	//   - partialResult: The player's partial result of the MPC session. Use
	//     partialsymmetric.FinalizeHMACPartialResult to combine the partial results received from the players into the
	//     final digest.
	HMACSHA256(ctx context.Context, sessionConfig *SessionConfig, keyID string, data []byte) (partialResult []byte, err error)

	// HMACSHA512 instructs this player to participate in an MPC session for generating a HMAC-SHA512 digest of some
	// provided data.
	//
	// The call blocks until all players are instructed to participate in the session, or the session times out
	// (default timeout is 10 seconds). All players in the session must agree on keyID, initialization vector (iv),
	// and keyStreamLength.
	//
	// Input:
	//   - keyID: The key to use for producing the HMAC-SHA512 digest.
	//   - data: The input data to HMAC-SHA512. Must be at most 16384 bytes.
	//
	// Output:
	//   - partialResult: The player's partial result of the MPC session. Use
	//     partialsymmetric.FinalizeHMACPartialResult to combine the partial results received from the players into the
	//     final digest.
	HMACSHA512(ctx context.Context, sessionConfig *SessionConfig, keyID string, data []byte) (partialResult []byte, err error)
}

type hmacService struct {
	*node
}

func (s *hmacService) GenerateKey(ctx context.Context, sessionConfig *SessionConfig, threshold, keyLength int, desiredKeyID string) (keyID string, err error) {
	if desiredKeyID != "" {
		if err = validateKeyID(desiredKeyID); err != nil {
			return "", toTSMError(err, ErrInvalidInput)
		}
	}

	res, err := s.call(ctx, http.MethodPost, "/hmac/keys/keygen", sessionConfig, s.sendAuthenticatedRequest,
		func() interface{} {
			return transport.HMACKeyGenRequest{
				Threshold:    threshold,
				KeyLength:    keyLength,
				DesiredKeyID: desiredKeyID,
			}
		},
	)
	if err != nil {
		return "", toTSMError(err, ErrOperationFailed)
	}

	var jsonResponse transport.HMACKeyGenResponse
	err = unmarshalJSON(res, &jsonResponse)
	if err != nil {
		return "", err
	}
	return jsonResponse.KeyID, nil
}

func (s *hmacService) ExportKeyShares(ctx context.Context, sessionConfig *SessionConfig, keyID string, wrappingKey []byte) (wrappedKeyShare *HMACWrappedKeyShare, err error) {
	if err = validateKeyID(keyID); err != nil {
		return nil, toTSMError(err, ErrInvalidInput)
	}

	res, err := s.call(ctx, http.MethodPost, fmt.Sprintf("/hmac/keys/%s/export", keyID), sessionConfig, s.sendAuthenticatedRequest,
		func() interface{} {
			return transport.HMACKeyExportRequest{
				WrappingKey: wrappingKey,
			}
		})
	if err != nil {
		return nil, toTSMError(err, ErrOperationFailed)
	}

	var jsonResponse transport.HMACKeyExportResponse
	err = unmarshalJSON(res, &jsonResponse)
	if err != nil {
		return nil, err
	}

	return &HMACWrappedKeyShare{
		WrappedKeyShare: jsonResponse.WrappedKeyShare,
		Checksum:        jsonResponse.Checksum,
	}, nil

}

func (s *hmacService) ImportKeyShares(ctx context.Context, sessionConfig *SessionConfig, threshold int, wrappedKeyShare, checksum []byte, desiredKeyID string) (keyID string, err error) {
	if desiredKeyID != "" {
		if err = validateKeyID(desiredKeyID); err != nil {
			return "", toTSMError(err, ErrInvalidInput)
		}
	}

	res, err := s.call(ctx, http.MethodPost, "/hmac/keys/import", sessionConfig, s.sendAuthenticatedRequest,
		func() interface{} {
			return transport.HMACKeyImportRequest{
				DesiredKeyID: desiredKeyID,
				Threshold:    threshold,
				KeyShare:     wrappedKeyShare,
				Checksum:     checksum,
			}
		},
	)
	if err != nil {
		return "", toTSMError(err, ErrOperationFailed)
	}

	var jsonResponse transport.HMACKeyImportResponse
	err = unmarshalJSON(res, &jsonResponse)
	if err != nil {
		return "", err
	}
	return jsonResponse.KeyID, nil
}

func (s *hmacService) HMACSHA256(ctx context.Context, sessionConfig *SessionConfig, keyID string, data []byte) (partialResult []byte, err error) {
	return s.hmac(ctx, sessionConfig, keyID, data, "/hmac/keys/%s/hmac256")
}

func (s *hmacService) HMACSHA512(ctx context.Context, sessionConfig *SessionConfig, keyID string, data []byte) (partialResult []byte, err error) {
	return s.hmac(ctx, sessionConfig, keyID, data, "/hmac/keys/%s/hmac512")
}

func (s *hmacService) hmac(ctx context.Context, sessionConfig *SessionConfig, keyID string, data []byte, path string) (partialResult []byte, err error) {
	if err := validateKeyID(keyID); err != nil {
		return nil, toTSMError(err, ErrInvalidInput)
	}

	res, err := s.call(ctx, http.MethodPost, fmt.Sprintf(path, keyID), sessionConfig, s.sendAuthenticatedRequest,
		func() interface{} {
			return transport.HMACSHA2Request{
				Data: data,
			}
		})
	if err != nil {
		return nil, toTSMError(err, ErrOperationFailed)
	}

	var jsonResponse transport.HMACSHA2Response
	err = unmarshalJSON(res, &jsonResponse)
	if err != nil {
		return nil, err
	}

	var r partialsymmetric.HMACPartialResult
	if err = r.Decode(jsonResponse.HMACPartialResult); err != nil {
		return nil, err
	}

	return r.Encode(), nil
}
