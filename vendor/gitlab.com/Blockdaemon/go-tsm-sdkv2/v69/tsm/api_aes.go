package tsm

import (
	"context"
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/transport"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/partialresults/partialsymmetric"
	"net/http"
)

// AESWrappedKeyShare contains a wrapped xor share of an AES key along with a checksum of the AES key itself.
type AESWrappedKeyShare struct {
	WrappedKeyShare []byte
	Checksum        []byte
}

type AESGCMEncryptResult struct {
	Ciphertext []byte
	Tag        []byte
}

// AESAPI provides functionality for generating, importing, and exporting AES keys, as well as various encryption
// modes (CTR, CBC, GCM). Both 128-bit, 192-bit, and 256-bit AES keys are supported.
type AESAPI interface {

	// GenerateKey instructs this player to participate in an MPC session that generates an AES key.
	//
	// All players in the session must agree on threshold, key length, and optionally a desired key ID.
	//
	// Input:
	//   - threshold: The security threshold for the key. Must be at least 1 and at most the total number of nodes
	//     minus one. The TSM guarantees that the key remains secure as long as at most threshold number of MPC nodes
	//     are corrupted.
	//   - keyLength: The length of the key to generate. Supported values are 16, 24 and 32 (for 128, 192, 256-bit AES
	//     keys, respectively).
	//   - desiredKeyID (optional): A unique string of length 28, containing only ASCII letters and numbers. If
	//     provided, the generated key will get this key ID.
	//
	// Output:
	//   - keyID: The ID of the new key. If desiredKeyID was provided, it will be output here.
	GenerateKey(ctx context.Context, sessionConfig *SessionConfig, threshold, keyLength int, desiredKeyID string) (keyID string, err error)

	// ExportKeyShares instructs the player to participate in an MPC session that exports key shares of an AES key.
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
	//   - wrappedKeyShare: A wrapped xor key share and checksum exported to this player. The actual key is computed
	//     as share1 xor share2 xor share3 ... where xor is bit-wise xor.
	ExportKeyShares(ctx context.Context, sessionConfig *SessionConfig, keyID string, wrappingKey []byte) (wrappedKeyShare *AESWrappedKeyShare, err error)

	// ImportKeyShares instructs the player to participate in an MPC session that imports key shares of an AES key.
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
	// The MPC session then starts. The MPC session first recovers the AES from the provided key shares.
	// If the optional checksum is provided, the session then computes the expected checksum as the first three bytes of
	// AES_Encrypt(key, msg), where msg is the message consisting of 16 0x01 byte, and then compares the provided
	// checksum with the expected checksum. If the checksum does not match the expected checksum, the MPC session
	// aborts. Finally, a secret sharing of the AES key is stored among the MPC nodes. The stored sharing is a new
	// independent sharing of the key, not related to the xor shares that was provided as input.
	//
	// To import from a source TSM to a target TSM, you first call WrappingKey() on each of the players in the target
	// TSM. Then call ExportKeyShares() on each of the players in the source TSM, providing the wrapping keys. The
	// output from ExportKeyShares() on the source TSM, along with the public key, obtained from PublicKey() on the
	// source TSM, can be used as input to ImportKeyShares() on the target TSM.
	//
	// If you instead want to import a private Schnorr key from somewhere else, you may want to use the helper functions
	// tsmutils.SecretShareAES() to split the key into shares, and tsmutils.Wrap() to wrap each share with the
	// wrapping keys obtained from calls to WrappingKey() on each of the players.
	//
	// Input:
	//   - threshold: The security threshold for the imported key.
	//   - wrappingKey: The wrapping key used to encrypt the key share exported to the player. Must be provided as
	//     SubjectPublicKeyInfo in an ASN.1 DER encoding (see RFC 5280, Section 4.1). The wrapping key of a target TSM
	//     can be obtained by WrappingKey().
	//   - wrappedKeyShare: The key share for this player, wrapped using the player's wrapping key, which can be
	//     obtained by WrappingKey().
	//   - checksum (optional): The first three bytes of AES_Encrypt(key, 0x01010101010101010101010101010101)
	//   - desiredKeyID (optional): A unique string of length 28, containing only ASCII letters and numbers. If
	//     provided, the imported key will get this key ID.
	//
	// Output:
	//   - keyID: The ID of the imported key. If desiredKeyID was provided, it will be output here.
	ImportKeyShares(ctx context.Context, sessionConfig *SessionConfig, threshold int, wrappedKeyShare, checksum []byte, desiredKeyID string) (keyID string, err error)

	// CTRKeyStream instructs this player to participate in an MPC session for generating an AES-CTR key stream.
	//
	// The call blocks until all players are instructed to participate in the session, or the session times out
	// (default timeout is 10 seconds). All players in the session must agree on keyID, initialization vector (iv),
	// and keyStreamLength.
	//
	// Input:
	//   - keyID: The key to use for producing the key stream.
	//   - iv: A 16-byte initialization vector used for producing the key stream.
	//   - keyStreamLength: The length of the key stream to generate. Must be at most 16384 bytes.
	//
	// Output:
	//   - partialResult: The player's partial result of the MPC session. Use FinalizeAESCTR to combine the partial
	//     results received from the players into the final AES-CTR key stream.
	CTRKeyStream(ctx context.Context, sessionConfig *SessionConfig, keyID string, iv []byte, keyStreamLength int) (partialResult []byte, err error)

	// CBCEncrypt instructs this player to participate in an MPC session for generating an AES-CBC encryption.
	//
	// The call blocks until all players are instructed to participate in the session, or the session times out
	// (default timeout is 10 seconds). All players in the session must agree on keyID, initialization vector (iv),
	// and plaintext.
	//
	// Input:
	//   - keyID: The key to use for producing the key stream.
	//   - iv: A 16-byte initialization vector used for producing the key stream.
	//   - plaintext: The plaintext to encrypt. Must be at most 16384 bytes.
	//
	// Output:
	//   - partialResult: The player's partial result of the MPC session. Use partialsymmetric.FinalizeAESCBCEncrypt to
	//     combine the partial results received from the players into the final AES-CBC encryption.
	CBCEncrypt(ctx context.Context, sessionConfig *SessionConfig, keyID string, iv, plaintext []byte) (partialResult []byte, err error)

	// CBCDecrypt instructs this player to participate in an MPC session for generating an AES-CBC decryption.
	//
	// The call blocks until all players are instructed to participate in the session, or the session times out
	// (default timeout is 10 seconds). All players in the session must agree on keyID, initialization vector (iv),
	// and ciphertext.
	//
	// Input:
	//   - keyID: The key to use for producing the key stream.
	//   - iv: A 16-byte initialization vector used for producing the key stream.
	//   - ciphertext: The ciphertext to decrypt. Must be at most 16384 bytes.
	//
	// Output:
	//   - partialResult: The player's partial result of the MPC session. Use partialsymmetric.FinalizeAESCBCDecrypt to
	//     combine the partial results received from the players into the final AES-CBC decryption.
	CBCDecrypt(ctx context.Context, sessionConfig *SessionConfig, keyID string, iv, ciphertext []byte) (partialResult []byte, err error)

	// GCMEncrypt instructs this player to participate in an MPC session for generating an AES-GCM encryption.
	//
	// The call blocks until all players are instructed to participate in the session, or the session times out
	// (default timeout is 10 seconds). All players in the session must agree on keyID, plaintext, additional data,
	// and initialization vector (iv).
	//
	// Input:
	//   - keyID: The key to use for producing the key stream.
	//   - iv: A 12-byte initialization vector used for producing the gcm encryption.
	//   - plaintext: The plaintext to encrypt. Must be at most 16384 bytes.
	//   - additionalData: Additional data to be authenticated by the AES-GCM algorithm. Must be at most 16384 bytes.
	//
	// Output:
	//   - partialResult: The player's partial result of the MPC session. Use partialsymmetric.FinalizeAESGCMEncrypt to
	//     combine the partial results received from the players into the final AES-GCM encryption and tag.
	GCMEncrypt(ctx context.Context, sessionConfig *SessionConfig, keyID string, iv, plaintext, additionalData []byte) (partialResult []byte, err error)

	// GCMDecrypt instructs this player to participate in an MPC session for generating an AES-GCM decryption.
	//
	// The call blocks until all players are instructed to participate in the session, or the session times out
	// (default timeout is 10 seconds). All players in the session must agree on keyID, initialization vector (iv),
	// additional data, and tag.
	//
	// Input:
	//   - keyID: The key to use for producing the key stream.
	//   - iv: A 12-byte initialization vector used for the gcm decryption.
	//   - ciphertext: The ciphertext to decrypt. Must be at most 16384 bytes.
	//   - additionalData: Additional data to be authenticated by the AES-GCM algorithm. Must be at most 16384 bytes.
	//   - tag: The 16-byte AES-GCM authentication tag.
	//
	// Output:
	//   - partialResult: The player's partial result of the MPC session. Use partialsymmetric.FinalizeAESGCMDecrypt to
	//     combine the partial results received from the players into the final AES-GCM plaintext.
	GCMDecrypt(ctx context.Context, sessionConfig *SessionConfig, keyID string, iv, ciphertext, additionalData, tag []byte) (partialResult []byte, err error)
}

type aesService struct {
	*node
}

func (s *aesService) GenerateKey(ctx context.Context, sessionConfig *SessionConfig, threshold, keyLength int, desiredKeyID string) (keyID string, err error) {
	if desiredKeyID != "" {
		if err = validateKeyID(desiredKeyID); err != nil {
			return "", toTSMError(err, ErrInvalidInput)
		}
	}

	res, err := s.call(ctx, http.MethodPost, "/aes/keys/keygen", sessionConfig, s.sendAuthenticatedRequest,
		func() interface{} {
			return transport.AESKeyGenRequest{
				Threshold:    threshold,
				KeyLength:    keyLength,
				DesiredKeyID: desiredKeyID,
			}
		},
	)
	if err != nil {
		return "", toTSMError(err, ErrOperationFailed)
	}

	var jsonResponse transport.AESKeyGenResponse
	err = unmarshalJSON(res, &jsonResponse)
	if err != nil {
		return "", err
	}
	return jsonResponse.KeyID, nil
}

func (s *aesService) ExportKeyShares(ctx context.Context, sessionConfig *SessionConfig, keyID string, wrappingKey []byte) (wrappedKeyShare *AESWrappedKeyShare, err error) {
	if err = validateKeyID(keyID); err != nil {
		return nil, toTSMError(err, ErrInvalidInput)
	}

	res, err := s.call(ctx, http.MethodPost, fmt.Sprintf("/aes/keys/%s/export", keyID), sessionConfig, s.sendAuthenticatedRequest,
		func() interface{} {
			return transport.AESKeyExportRequest{
				WrappingKey: wrappingKey,
			}
		})
	if err != nil {
		return nil, toTSMError(err, ErrOperationFailed)
	}

	var jsonResponse transport.AESKeyExportResponse
	err = unmarshalJSON(res, &jsonResponse)
	if err != nil {
		return nil, err
	}

	return &AESWrappedKeyShare{
		WrappedKeyShare: jsonResponse.WrappedKeyShare,
		Checksum:        jsonResponse.Checksum,
	}, nil

}

func (s *aesService) ImportKeyShares(ctx context.Context, sessionConfig *SessionConfig, threshold int, wrappedKeyShare, checksum []byte, desiredKeyID string) (keyID string, err error) {
	if desiredKeyID != "" {
		if err = validateKeyID(desiredKeyID); err != nil {
			return "", toTSMError(err, ErrInvalidInput)
		}
	}

	res, err := s.call(ctx, http.MethodPost, "/aes/keys/import", sessionConfig, s.sendAuthenticatedRequest,
		func() interface{} {
			return transport.AESKeyImportRequest{
				Threshold:    threshold,
				KeyShare:     wrappedKeyShare,
				Checksum:     checksum,
				DesiredKeyID: desiredKeyID,
			}
		},
	)
	if err != nil {
		return "", toTSMError(err, ErrOperationFailed)
	}

	var jsonResponse transport.AESKeyImportResponse
	err = unmarshalJSON(res, &jsonResponse)
	if err != nil {
		return "", err
	}
	return jsonResponse.KeyID, nil
}

func (s *aesService) CTRKeyStream(ctx context.Context, sessionConfig *SessionConfig, keyID string, iv []byte, keyStreamLength int) (ctrResult []byte, err error) {
	if err = validateKeyID(keyID); err != nil {
		return nil, toTSMError(err, ErrInvalidInput)
	}

	url := fmt.Sprintf("/aes/keys/%s/ctr-keystream", keyID)
	res, err := s.call(ctx, http.MethodPost, url, sessionConfig, s.sendAuthenticatedRequest,
		func() interface{} {
			return transport.AESCTRRequest{
				IV:              iv,
				KeyStreamLength: keyStreamLength,
			}
		})
	if err != nil {
		return nil, toTSMError(err, ErrOperationFailed)
	}

	var jsonResponse transport.AESCTRResponse
	err = unmarshalJSON(res, &jsonResponse)
	if err != nil {
		return nil, err
	}

	var r partialsymmetric.AESCTRPartialResult
	if err = r.Decode(jsonResponse.PartialAESCTRResult); err != nil {
		return nil, err
	}

	return r.Encode(), nil

}

func (s *aesService) CBCEncrypt(ctx context.Context, sessionConfig *SessionConfig, keyID string, iv, plaintext []byte) (partialResult []byte, err error) {
	if err := validateKeyID(keyID); err != nil {
		return nil, toTSMError(err, ErrInvalidInput)
	}

	url := fmt.Sprintf("/aes/keys/%s/cbc-encrypt", keyID)
	response, err := s.call(ctx, http.MethodPost, url, sessionConfig, s.sendAuthenticatedRequest,
		func() interface{} {
			return transport.AESCBCEncryptRequest{
				IV:        iv,
				Plaintext: plaintext,
			}
		})
	if err != nil {
		return nil, toTSMError(err, ErrOperationFailed)
	}

	var jsonResponse transport.AESCBCEncryptResponse
	err = unmarshalJSON(response, &jsonResponse)
	if err != nil {
		return nil, err
	}

	var result partialsymmetric.AESCBCEncryptPartialResult
	if err = result.Decode(jsonResponse.PartialAESCBCEncryptResult); err != nil {
		return nil, err
	}

	return result.Encode(), nil

}

func (s *aesService) CBCDecrypt(ctx context.Context, sessionConfig *SessionConfig, keyID string, iv, ciphertext []byte) (partialResult []byte, err error) {
	if err := validateKeyID(keyID); err != nil {
		return nil, toTSMError(err, ErrInvalidInput)
	}

	url := fmt.Sprintf("/aes/keys/%s/cbc-decrypt", keyID)
	response, err := s.call(ctx, http.MethodPost, url, sessionConfig, s.sendAuthenticatedRequest,
		func() interface{} {
			return transport.AESCBCDecryptRequest{
				IV:         iv,
				Ciphertext: ciphertext,
			}
		})
	if err != nil {
		return nil, toTSMError(err, ErrOperationFailed)
	}

	var jsonResponse transport.AESCBCDecryptResponse
	err = unmarshalJSON(response, &jsonResponse)
	if err != nil {
		return nil, err
	}

	var result partialsymmetric.AESCBCDecryptPartialResult
	if err = result.Decode(jsonResponse.PartialAESCBCDecryptResult); err != nil {
		return nil, err
	}

	return result.Encode(), nil

}

func (s *aesService) GCMEncrypt(ctx context.Context, sessionConfig *SessionConfig, keyID string, iv, plaintext, additionalData []byte) (partialResult []byte, err error) {
	if err := validateKeyID(keyID); err != nil {
		return nil, toTSMError(err, ErrInvalidInput)
	}

	url := fmt.Sprintf("/aes/keys/%s/gcm-encrypt", keyID)
	response, err := s.call(ctx, http.MethodPost, url, sessionConfig, s.sendAuthenticatedRequest,
		func() interface{} {
			return transport.AESGCMEncryptRequest{
				IV:             iv,
				Plaintext:      plaintext,
				AdditionalData: additionalData,
			}
		})
	if err != nil {
		return nil, toTSMError(err, ErrOperationFailed)
	}

	var jsonResponse transport.AESGCMEncryptResponse
	err = unmarshalJSON(response, &jsonResponse)
	if err != nil {
		return nil, err
	}

	var result partialsymmetric.AESGCMEncryptPartialResult
	if err = result.Decode(jsonResponse.PartialAESGCMEncryptResult); err != nil {
		return nil, err
	}

	return result.Encode(), nil

}

func (s *aesService) GCMDecrypt(ctx context.Context, sessionConfig *SessionConfig, keyID string, iv, ciphertext, additionalData, tag []byte) (partialResult []byte, err error) {
	if err := validateKeyID(keyID); err != nil {
		return nil, toTSMError(err, ErrInvalidInput)
	}

	url := fmt.Sprintf("/aes/keys/%s/gcm-decrypt", keyID)
	response, err := s.call(ctx, http.MethodPost, url, sessionConfig, s.sendAuthenticatedRequest,
		func() interface{} {
			return transport.AESGCMDecryptRequest{
				IV:             iv,
				Ciphertext:     ciphertext,
				AdditionalData: additionalData,
				Tag:            tag,
			}
		})
	if err != nil {
		return nil, toTSMError(err, ErrOperationFailed)
	}

	var jsonResponse transport.AESGCMDecryptResponse
	err = unmarshalJSON(response, &jsonResponse)
	if err != nil {
		return nil, err
	}

	var result partialsymmetric.AESGCMDecryptPartialResult
	if err = result.Decode(jsonResponse.PartialAESGCMDecryptResult); err != nil {
		return nil, err
	}

	return result.Encode(), nil

}
