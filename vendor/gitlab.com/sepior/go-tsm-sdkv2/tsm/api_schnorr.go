package tsm

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"gitlab.com/sepior/go-tsm-sdkv2/internal/transport"
	"gitlab.com/sepior/go-tsm-sdkv2/ec"
	"gitlab.com/sepior/go-tsm-sdkv2/internal/partialresults/partialsignature"
	"gitlab.com/sepior/go-tsm-sdkv2/internal/secretshare"
	"io"
	"net/http"
)

// SchnorrPartialSignResult contains a partial signature as well as the ID of the presignature used to produce it. The
// presignature ID is empty if the partial signature was generated without presignatures.
type SchnorrPartialSignResult struct {
	PresignatureID   string
	PartialSignature []byte
}

// SchnorrRecoveredPrivateKey contains a raw Schnorr private key in big endian format as well as the master chain code.
type SchnorrRecoveredPrivateKey struct {
	PrivateKey      []byte
	MasterChainCode []byte
}

// SchnorrWrappedKeyShare contains a wrapped (encrypted) key share and chain code as well as the corresponding public key.
type SchnorrWrappedKeyShare struct {
	WrappedKeyShare  []byte
	WrappedChainCode []byte
	PKIXPublicKey    []byte
}

// SchnorrAPI provides functionality related to Schnorr keys and signatures. Depending on the elliptic curve used,
// it provides different flavours of Schnorr signatures. Currently, Ed25519, Ed448 and BIP-340 are supported.
//
// # Compliance with RFC 8032 (Ed25519 and Ed448)
//
// The API treats the raw scalar as the private key and does not derive the scalar from an initial
// seed as described in RFC 8032 (https://datatracker.ietf.org/doc/html/rfc8032).
//
// The TSM does not use deterministic signing as specified by RFC 8032. Instead, the
// TSM uses MPC to sample a fresh random signing nonce for each signature.
//
// # Deterministic Key Derivation
//
// The TSM supports BIP-32 like non-hardened derivation for Ed25519 and Ed448 keys. The non-hardened derivation
// for these keys uses multiplicative rather than additive offsets. For BIP-340 keys the TSM supports non-hardened
// BIP-32.
type SchnorrAPI interface {
	// GenerateKey instructs this player to participate in an MPC session that generates a Schnorr key.
	//
	// All players in the session must agree on threshold, curveName, and desiredKeyID.
	//
	// Input:
	//   - threshold: The security threshold for the key. Must be at least 1 and at most the total number of nodes minus
	//     one.
	//     The TSM guarantees that the key remains secure as long as at most threshold number of MPC nodes are corrupted.
	//   - curveName: The elliptic curve for the key. Must be one of "ED-25519" (for Ed25519), "ED-448" (for Ed448) or
	//     "secp256k1" (for BIP-340)
	//   - desiredKeyID (optional): A unique string of length 28, containing only ASCII letters and numbers. If provided,
	//     the generated key will get this key ID.
	//
	// Output:
	//   - keyID: The ID of the new key. If desiredKeyID was provided, it will be output here.
	GenerateKey(ctx context.Context, sessionConfig *SessionConfig, threshold int, curveName string, desiredKeyID string) (keyID string, err error)

	// GeneratePresignatures instructs this player to participate in an MPC session that generates a number of
	// presignatures for a Schnorr key.
	//
	// All players in the session must agree on keyID and presignatureCount. The call blocks until all players are
	// instructed to participate in the session, or the session times out (default timeout is 10 seconds).
	GeneratePresignatures(ctx context.Context, sessionConfig *SessionConfig, keyID string, presignatureCount uint64) (presignatureIDs []string, err error)

	// Sign instructs this player to participate in an MPC session for generating a Schnorr signature.
	//
	// All players in the session must agree on keyID, chainPath, and message. The call blocks until all players are
	// instructed to participate in the session, or the session times out (default timeout is 10 seconds).
	//
	// Input:
	//   - keyID: The ID of an existing Schnorr key to use for signing.
	//   - derivationPath (optional): If nil, the key defined by keyID is used for signing.
	//     The derivationPath may optionally specify a derivation path, and if so, signing is done using the key
	//     derived from the key defined by keyID, using the given derivation path. The derivationPath must be a non-hardened
	//     derivation path of depth at most 50; i.e., derivationPath may be a list of at most 50 uint32 values, each value greater
	//     or equal to 0 and less than 2^31.
	//   - message: The message to be signed. Note that this is the message itself and not a hash of the message.
	//
	// Output:
	//   - signResult: The partial signature for this player. Use SchnorrFinalizeSignature to combine partial signatures
	//     into a full Schnorr signature.
	Sign(ctx context.Context, sessionConfig *SessionConfig, keyID string, derivationPath []uint32, message []byte) (signResult *SchnorrPartialSignResult, err error)

	// SignWithPresignature creates a partial Schnorr signature.
	//
	// Works as Sign(), except that a presignature is consumed by SignWithPresignature(), and the presignature allows
	// this player to locally compute the partial signature without participating in any MPC session that requires
	// communication between the players.
	//
	// If presignatureID is empty, the player instead uses a random unused presignature, and its ID is returned as part
	// of the signResult.
	//
	// In order to produce a valid signature, all involved players must agree on the presignature to use.
	SignWithPresignature(ctx context.Context, keyID string, presignatureID string, derivationPath []uint32, message []byte) (signResult *SchnorrPartialSignResult, err error)

	// GenerateRecoveryData instructs this player to participate in an MPC session that generates recovery data for a
	// Schnorr key.
	//
	// The recovery data consists of all the private key shares and the chain code, all encrypted under the ERS public
	// key and using the provided ersLabel as OAEP label. The recovery data also includes a zero-knowledge proof that
	// can be used to validate the recovery data without the ERS private key.
	//
	// Once all the partial recovery data have been gathered from the players, they can be combined to a single complete
	// recovery data using the method SchnorrFinalizeRecoveryData(). Later, SchnorrValidateRecoveryData() can be used to
	// validate correctness of the complete recovery data. Finally, SchnorrRecoverPrivateKey() can be used to recover the
	// full private key from the complete recovery data.
	//
	// All players in the session must agree on keyID, ersPublicKey, and ersLabel. The call blocks until all players are
	// instructed to participate in the session, or the session times out (default timeout is 10 seconds).
	//
	// Input:
	//   - keyID: The Schnorr key for which to generate recovery data.
	//   - ersPublicKey: The ERS public key used to encrypt the recovery data. Must be an RSA key as the
	//     SubjectPublicKeyInfo of an ASN.1 DER encoding. The RSA key must be large enough to directly encrypt scalars
	//     using RSA-OAEP-SHA256 encrypted. A 2048-bit RSA key suffices for all currently supported curves.
	//   - ersLabel (optional): An OAEP label which can be verified by the ERS decryption service.
	//
	// Output:
	//   - partialRecoveryData: The partial recovery data for this player. Use SchnorrFinalizeRecoveryData() to combine
	//     partial recovery data into the final recovery data.
	GenerateRecoveryData(ctx context.Context, sessionConfig *SessionConfig, keyID string, ersPublicKey *rsa.PublicKey, ersLabel []byte) (partialRecoveryData []byte, err error)

	// PublicKey returns the public key corresponding to a given Schnorr key in the TSM.
	//
	// CAVEAT: Only use the returned public key, e.g., for creating an address on a blockchain, if you trust this player.
	// External parties should generally only trust a public key from the TSM if it was obtained from at least
	// threshold + 1 different players, and all the obtained public keys are identical.
	//
	// Input:
	//   - keyID: The ID of a Schnorr key in the TSM.
	//   - derivationPath (optional): If nil, the public key defined by keyID is returned.
	//     The derivationPath may optionally specify a derivation path, and if so, the public key returned is
	//     derived from the key defined by keyID, using the given derivation path. The derivationPath must be a non-hardened
	//     and of depth at most 50; i.e., derivationPath may be a list of at most 50 uint32 values, each value greater or
	//     equal to 0 and less than 2^31.
	//
	// Output:
	//   - pkixPublicKey: A public Schnorr key as the SubjectPublicKeyInfo of an ASN.1 DER encoding.
	PublicKey(ctx context.Context, keyID string, derivationPath []uint32) (pkixPublicKey []byte, err error)

	// ChainCode returns the chain code for a Schnorr key.
	//
	// CAVEAT: Only use the returned chain code, e.g., for creating an address on a blockchain, if you trust this player.
	// External parties should generally only trust a chain code from the TSM if it was obtained from at least
	// threshold + 1 different players, and all the obtained chain codes are identical.
	//
	// Input:
	//   - keyID: The ID of a Schnorr key in the TSM.
	//   - derivationPath (optional): If nil, the chain code for the key defined by keyID is returned.
	//     The derivationPath may optionally specify a derivation path, and if so, the returned chain code is
	//     derived from the key defined by keyID, using the given derivation path. Must be a non-hardened and of
	//     depth at most 50; i.e., derivationPath may be a list of at most 50 uint32 values, each value greater or equal
	//     to 0 and less than 2^31.
	ChainCode(ctx context.Context, keyID string, derivationPath []uint32) (chainCode []byte, err error)

	// Reshare instructs this player to participate in an MPC session that refreshes the secret sharing of a Schnorr key.
	//
	// All players in the session must agree on the keyID. The call blocks until all players are instructed to
	// participate in the session, or the session times out (default timeout is 10 seconds).
	//
	// The Schnorr key remains unchanged by this operation, but the secret sharing of the key will be replaced with a new
	// random and independent secret sharing of the same key.
	//
	// CAVEAT: Reshare() invalidates all existing key shares of the key, including shares that are kept in a backup.
	//
	// Reshare() automatically deletes any existing presignatures for the key.
	//
	// If the operation fails for some reason, it should be retried until it succeeds. After this operation is called
	// for the first time and until it succeeds, other operations involving the same key might fail.
	Reshare(ctx context.Context, sessionConfig *SessionConfig, keyID string) error

	// BackupKeyShare returns an unprotected backup of a key share.
	//
	// This is intended for backup of a key share on a mobile phone. The backup can later be used to restore the key share
	// using RestoreKeyShare().
	//
	// BackupShare() only works if explicitly enabled in the MPC node configuration.
	//
	// CAVEAT: The exported backup is not protected, and it is up to the caller to add protection to the backup to
	// prevent the key share from being leaked.
	//
	// Input:
	//   - keyID: The ID of an existing Schnorr key in the TSM.
	//
	// Output:
	//   - shareBackup: An internal encoding that includes the key ID and key share.
	BackupKeyShare(ctx context.Context, keyID string) (keyShareBackup []byte, err error)

	// RestoreKeyShare restores a key share.
	//
	// CAVEAT: Restoring a share from a backup created prior to calling Reshare() will not work, unless all players
	// agree to restore their old shares.
	//
	// Input:
	//   - keyShareBackup: The share backup, as produced by BackupKeyShare(). The backup cannot be restored if a key
	//     with the same keyID exists.
	//
	// Output:
	//   - keyID: The ID of the key whose share was recovered.
	RestoreKeyShare(ctx context.Context, keyShareBackup []byte) (keyID string, err error)

	// ExportKeyShares instructs the player to participate in an MPC session that exports key shares of an ECDSA key.
	//
	// All players in the session must agree on keyID and chainPath. The call blocks until all players are instructed to
	// participate in the session, or the session times out (default timeout is 10 seconds).
	//
	// The public key and chain code as well as a share of the private key is exported to each player. The exported
	// private key share and chain code are encrypted under the wrapping key provided to that player.
	//
	// The MPC session generates a new, independent secret sharing of the key and uses the new shares for export.
	// The secret sharing of the key in the TSM is not changed, and the new sharing is only used for this export,
	//
	// If a chainPath is provided, the exported key shares will be shares of a key derived from the key defined by keyID,
	// using the provided chainPath.
	//
	// Each player is configured with a whitelist of wrapping keys and only accepts to export if the provided wrapping
	// key matches the whitelist.
	//
	// Input:
	//   - keyID: The ID of an existing Schnorr key in the TSM.
	//   - derivationPath (optional): Must be a non-hardened derivation path of depth at most 50; i.e., derivationPath
	//     may be a list of at most 50 uint32 values, each value greater or equal to 0 and less than 2^31.
	//   - wrappingKey: The wrapping key used to encrypt the key share exported to the player. Must be provided as
	//     SubjectPublicKeyInfo in an ASN.1 DER encoding (see RFC 5280, Section 4.1). The wrapping key of a target TSM
	//     can be obtained by WrappingKey().
	//
	// Output:
	//   - wrappedKeyShare: The wrapped key share and chain code exported to this player. The key share also contains
	//     the public key corresponding to the exported private key shares.
	ExportKeyShares(ctx context.Context, sessionConfig *SessionConfig, keyID string, derivationPath []uint32, wrappingKey []byte) (wrappedKeyShare *SchnorrWrappedKeyShare, err error)

	// ImportKeyShares instructs the player to participate in an MPC session that imports key shares of a Schnorr key.
	//
	// The import session only succeeds if all players in the session agree on the threshold, the public key, and the
	// chain code. In addition, the session aborts unless the shares provided by the players form a private ECDSA key
	// that matches the provided public ECDSA key. The call blocks until all players are instructed to participate in
	// the session, or the session times out (default timeout is 10 seconds).
	//
	// The key share and chain code is first decrypted by the player, using the private unwrapping key.
	// The MPC session then starts, and the above conditions are checked. If satisfied, a new and independent secret
	// sharing of the key is generated and the corresponding shares stored by each player.
	//
	// To import from a source TSM to a target TSM, you first call WrappingKey() on each of the players in the target
	// TSM. Then call ExportKeyShares() on each of the players in the source TSM, providing the wrapping keys. The
	// output from ExportKeyShares() on the source TSM, along with the public key, obtained from PublicKey() on the
	// source TSM, can be used as input to ImportKeyShares() on the target TSM.
	//
	// If you instead want to import a private Schnorr key from somewhere else, you may want to use the helper functions
	// tsmutils.ShamirSecretShare() to split the key into shares, and tsmutils.Wrap() to wrap each share with the
	// wrapping keys obtained from calls to WrappingKey() on each of the players.
	//
	// Input:
	//   - threshold: The security threshold for the imported key. The ID of an existing ECDSA key in the TSM.
	//   - wrappingKey: The wrapping key used to encrypt the key share exported to the player. Must be provided as
	//     SubjectPublicKeyInfo in an ASN.1 DER encoding (see RFC 5280, Section 4.1). The wrapping key of a target TSM
	//     can be obtained by WrappingKey().
	//   - wrappedKeyShare: The key share for this player, wrapped using the player's wrapping key, which can be
	//     obtained by WrappingKey().
	//   - wrappedChainCode (optional): The chain code for the key, wrapped under the player's wrapping key, which can be
	//     obtained by WrappingKey(). If nil, a random chain code will be generated.
	//   - pkixPublicKey: The public key corresponding to the imported key shares, as SubjectPublicKeyInfo of an ASN.1
	//     DER encoding (see RFC 5280, Section 4.1). The public key is used to validate the imported shares; the import
	//     session fails if the imported shares does not match the provided pkixPublicKey.
	//
	// Output:
	//   - keyID: The ID of the imported key.
	ImportKeyShares(ctx context.Context, sessionConfig *SessionConfig, threshold int, wrappedKeyShare []byte, wrappedChainCode []byte, pkixPublicKey []byte, desiredKeyID string) (keyID string, err error)
}

type schnorrService struct {
	*node
}

func (s *schnorrService) GenerateKey(ctx context.Context, sessionConfig *SessionConfig, threshold int, curveName string, desiredKeyID string) (keyID string, err error) {
	if desiredKeyID != "" {
		if err = validateKeyID(desiredKeyID); err != nil {
			return "", toTSMError(err, ErrInvalidInput)
		}
	}

	res, err := s.call(ctx, http.MethodPost, "/schnorr/keys", sessionConfig, s.sendAuthenticatedRequest,
		func() interface{} {
			return transport.SchnorrKeyGenRequest{
				Threshold: threshold,
				Curve:     curveName,
				KeyID:     desiredKeyID,
			}
		})
	if err != nil {
		return "", toTSMError(err, ErrOperationFailed)
	}

	var jsonResponse transport.SchnorrKeyGenResponse
	err = unmarshalJSON(res, &jsonResponse)
	if err != nil {
		return "", err
	}
	return jsonResponse.KeyID, nil
}

func (s *schnorrService) GeneratePresignatures(ctx context.Context, sessionConfig *SessionConfig, keyID string, presignatureCount uint64) (presignatureIDs []string, err error) {
	if err = validateKeyID(keyID); err != nil {
		return nil, toTSMError(err, ErrInvalidInput)
	}

	res, err := s.call(ctx, http.MethodPost, fmt.Sprintf("/schnorr/keys/%s/%d/presiggen", keyID, presignatureCount), sessionConfig, s.sendAuthenticatedRequest, nil)
	if err != nil {
		return nil, toTSMError(err, ErrOperationFailed)
	}

	var jsonResponse transport.SchnorrPresigGenResponse
	err = unmarshalJSON(res, &jsonResponse)
	if err != nil {
		return nil, err
	}

	if uint64(len(jsonResponse.IDs)) != presignatureCount {
		return nil, toTSMError(errors.New("invalid number of presignature IDs returned"), ErrOperationFailed)
	}

	return jsonResponse.IDs, nil
}

func (s *schnorrService) Sign(ctx context.Context, sessionConfig *SessionConfig, keyID string, derivationPath []uint32, message []byte) (signResult *SchnorrPartialSignResult, err error) {
	if err = validateKeyID(keyID); err != nil {
		return nil, toTSMError(err, ErrInvalidInput)
	}

	res, err := s.call(ctx, http.MethodPost, fmt.Sprintf("/schnorr/keys/%s/sign", keyID), sessionConfig, s.sendAuthenticatedRequest,
		func() interface{} {
			return transport.SchnorrSignRequest{
				ChainPath: derivationPath,
				Message:   message,
			}
		})
	if err != nil {
		return nil, toTSMError(err, ErrOperationFailed)
	}

	signResult, err = s.parseSignResponse(res)
	if err != nil {
		return nil, toTSMError(err, ErrOperationFailed)
	}

	return signResult, nil
}

func (s *schnorrService) SignWithPresignature(ctx context.Context, keyID string, presignatureID string, derivationPath []uint32, message []byte) (signResult *SchnorrPartialSignResult, err error) {
	if err = validateKeyID(keyID); err != nil {
		return nil, toTSMError(err, ErrInvalidInput)
	}

	res, err := s.call(ctx, http.MethodPost, fmt.Sprintf("/schnorr/keys/%s/signwithpresig", keyID), &SessionConfig{}, s.sendAuthenticatedRequest,
		func() interface{} {
			return transport.SchnorrSignWithPresigRequest{
				ChainPath:      derivationPath,
				Message:        message,
				PresignatureID: presignatureID,
			}
		})
	if err != nil {
		return nil, toTSMError(err, ErrOperationFailed)
	}

	signResult, err = s.parseSignResponse(res)
	if err != nil {
		return nil, toTSMError(err, ErrOperationFailed)
	}

	return signResult, nil
}

func (s *schnorrService) GenerateRecoveryData(ctx context.Context, sessionConfig *SessionConfig, keyID string, ersPublicKey *rsa.PublicKey, ersLabel []byte) (partialRecoveryData []byte, err error) {
	if err = validateKeyID(keyID); err != nil {
		return nil, toTSMError(err, ErrInvalidInput)
	}

	res, err := s.call(ctx, http.MethodPost, fmt.Sprintf("/schnorr/keys/%s/recoveryinfo", keyID), sessionConfig, s.sendAuthenticatedRequest,
		func() interface{} {
			return transport.SchnorrRecoveryInfoRequest{
				ERSPublicKey:      *ersPublicKey,
				Label:             ersLabel,
				OutputPlayerIndex: -1,
			}
		})
	if err != nil {
		return nil, toTSMError(err, ErrOperationFailed)
	}

	var jsonResponse transport.SchnorrRecoveryInfoResponse
	err = unmarshalJSON(res, &jsonResponse)
	if err != nil {
		return nil, err
	}

	out, err := json.Marshal(jsonResponse.RecoveryInfos[0])
	if err != nil {
		return nil, toTSMError(err, ErrOperationFailed)
	}
	return out, nil
}

func (s *schnorrService) PublicKey(ctx context.Context, keyID string, derivationPath []uint32) (pkixPublicKey []byte, err error) {
	if err = validateKeyID(keyID); err != nil {
		return nil, toTSMError(err, ErrInvalidInput)
	}

	res, err := s.call(ctx, http.MethodPost, fmt.Sprintf("/schnorr/keys/%s/publickey", keyID), &SessionConfig{}, s.sendAuthenticatedRequest,
		func() interface{} {
			return transport.SchnorrPublicKeyRequest{
				ChainPath: derivationPath,
			}
		})
	if err != nil {
		return nil, toTSMError(err, ErrOperationFailed)
	}

	var jsonResponse transport.SchnorrPublicKeyResponse
	err = unmarshalJSON(res, &jsonResponse)
	if err != nil {
		return nil, err
	}

	curve, err := ec.NewCurve(jsonResponse.Curve)
	if err != nil {
		return nil, toTSMError(fmt.Errorf("public key: unable to instantiate elliptic curve: %w", err), ErrOperationFailed)
	}
	ecPublicKey, err := curve.DecodePoint(jsonResponse.PublicKey, true)
	if err != nil {
		return nil, toTSMError(fmt.Errorf("public key: unable to decode public key: %w", err), ErrOperationFailed)
	}

	pkixPublicKey, err = schnorrPointToPKIXPublicKey(ecPublicKey)
	if err != nil {
		return nil, toTSMError(fmt.Errorf("public key: unable to encode public key: %w", err), ErrOperationFailed)
	}

	return pkixPublicKey, nil
}

func (s *schnorrService) ChainCode(ctx context.Context, keyID string, derivationPath []uint32) (chainCode []byte, err error) {
	if err = validateKeyID(keyID); err != nil {
		return nil, toTSMError(err, ErrInvalidInput)
	}

	response, err := s.call(ctx, http.MethodPost, fmt.Sprintf("/schnorr/keys/%s/chaincode", keyID), &SessionConfig{}, s.sendAuthenticatedRequest,
		func() interface{} {
			return transport.SchnorrChainCodeRequest{
				ChainPath: derivationPath,
			}
		})
	if err != nil {
		return nil, toTSMError(err, ErrInvalidInput)
	}

	var jsonResponse transport.SchnorrChainCodeResponse
	err = unmarshalJSON(response, &jsonResponse)
	if err != nil {
		return nil, toTSMError(err, ErrOperationFailed)
	}

	return jsonResponse.ChainCode, nil
}

func (s *schnorrService) Reshare(ctx context.Context, sessionConfig *SessionConfig, keyID string) error {
	if err := validateKeyID(keyID); err != nil {
		return toTSMError(err, ErrInvalidInput)
	}

	_, err := s.call(ctx, http.MethodPost, fmt.Sprintf("/schnorr/keys/%s/reshare", keyID), sessionConfig, s.sendAuthenticatedRequest, nil)
	if err != nil {
		return toTSMError(err, ErrOperationFailed)
	}
	return nil
}

func (s *schnorrService) BackupKeyShare(ctx context.Context, keyID string) (keyShareBackup []byte, err error) {
	if err = validateKeyID(keyID); err != nil {
		return nil, toTSMError(err, ErrInvalidInput)
	}

	response, err := s.call(ctx, http.MethodGet, fmt.Sprintf("/schnorr/keys/%s/backupshare", keyID), &SessionConfig{}, s.sendAuthenticatedRequest, nil)
	if err != nil {
		return nil, toTSMError(err, ErrInvalidInput)
	}

	var jsonResponse transport.SchnorrBackupResponse
	err = unmarshalJSON(response, &jsonResponse)
	if err != nil {
		return nil, toTSMError(err, ErrOperationFailed)
	}

	return jsonResponse.ShareBackup, nil
}

func (s *schnorrService) RestoreKeyShare(ctx context.Context, keyShareBackup []byte) (keyID string, err error) {
	response, err := s.call(ctx, http.MethodPost, "/schnorr/keys/restoreshare", &SessionConfig{}, s.sendAuthenticatedRequest,
		func() interface{} {
			return transport.SchnorrRestoreRequest{
				ShareBackup: keyShareBackup,
			}
		})
	if err != nil {
		return "", toTSMError(err, ErrInvalidInput)
	}

	var jsonResponse transport.SchnorrRestoreResponse
	err = unmarshalJSON(response, &jsonResponse)
	if err != nil {
		return "", toTSMError(err, ErrOperationFailed)
	}

	return jsonResponse.KeyID, nil
}

func (s *schnorrService) ExportKeyShares(ctx context.Context, sessionConfig *SessionConfig, keyID string, derivationPath []uint32, wrappingKey []byte) (wrappedKeyShare *SchnorrWrappedKeyShare, err error) {
	if err = validateKeyID(keyID); err != nil {
		return nil, toTSMError(err, ErrInvalidInput)
	}

	res, err := s.call(ctx, http.MethodPost, fmt.Sprintf("/schnorr/keys/%s/export", keyID), sessionConfig, s.sendAuthenticatedRequest,
		func() interface{} {
			return transport.SchnorrKeyExportRequest{
				WrappingKey: wrappingKey,
				ChainPath:   derivationPath,
			}
		})
	if err != nil {
		return nil, toTSMError(err, ErrOperationFailed)
	}

	var jsonResponse transport.SchnorrKeyExportResponse
	err = unmarshalJSON(res, &jsonResponse)
	if err != nil {
		return nil, err
	}

	curve, err := ec.NewCurve(jsonResponse.Curve)
	if err != nil {
		return nil, toTSMError(fmt.Errorf("export key shares: unable to instantiate elliptic curve: %w", err), ErrOperationFailed)
	}
	ecPublicKey, err := curve.DecodePoint(jsonResponse.PublicKey, true)
	if err != nil {
		return nil, toTSMError(fmt.Errorf("export key shares: unable to decode public key: %w", err), ErrOperationFailed)
	}

	pkixPublicKey, err := schnorrPointToPKIXPublicKey(ecPublicKey)
	if err != nil {
		return nil, toTSMError(fmt.Errorf("export key shares: unable to encode public key: %w", err), ErrOperationFailed)
	}

	return &SchnorrWrappedKeyShare{
		WrappedKeyShare:  jsonResponse.EncryptedKeyShare,
		WrappedChainCode: jsonResponse.EncryptedChainCode,
		PKIXPublicKey:    pkixPublicKey,
	}, nil
}

func (s *schnorrService) ImportKeyShares(ctx context.Context, sessionConfig *SessionConfig, threshold int, wrappedKeyShare []byte, wrappedChainCode []byte, pkixPublicKey []byte, desiredKeyID string) (keyID string, err error) {
	if desiredKeyID != "" {
		if err = validateKeyID(desiredKeyID); err != nil {
			return "", toTSMError(err, ErrInvalidInput)
		}
	}

	publicKey, err := schnorrPKIXPublicKeyToPoint(pkixPublicKey)
	if err != nil {
		return "", toTSMError(fmt.Errorf("import key shares: unable to decode public key: %w", err), ErrInvalidInput)
	}

	res, err := s.call(ctx, http.MethodPost, "/schnorr/keys/import", sessionConfig, s.sendAuthenticatedRequest,
		func() interface{} {
			return transport.SchnorrKeyImportRequest{
				KeyID:     desiredKeyID,
				Threshold: threshold,
				Curve:     publicKey.Curve().Name(),
				PublicKey: publicKey.Encode(),
				KeyShare:  wrappedKeyShare,
				ChainCode: wrappedChainCode,
			}
		})
	if err != nil {
		return "", toTSMError(err, ErrOperationFailed)
	}

	var jsonResponse transport.SchnorrKeyImportResponse
	err = unmarshalJSON(res, &jsonResponse)
	if err != nil {
		return "", err
	}

	return jsonResponse.KeyID, nil
}

func (s *schnorrService) parseSignResponse(response io.Reader) (*SchnorrPartialSignResult, error) {
	var jsonResponse transport.SchnorrSignResponse
	err := unmarshalJSON(response, &jsonResponse)
	if err != nil {
		return nil, err
	}

	curve, err := ec.NewCurve(jsonResponse.Curve)
	if err != nil {
		return nil, fmt.Errorf("sign response: unable to instantiate elliptic curve: %w", err)
	}
	sShare, err := curve.Zn().DecodeScalar(jsonResponse.SShare)
	if err != nil {
		return nil, fmt.Errorf("sign response: unable to decode signature share: %w", err)
	}
	publicKey, err := curve.DecodePoint(jsonResponse.PublicKey, true)
	if err != nil {
		return nil, fmt.Errorf("sign response: unable to decode public key: %w", err)
	}
	R, err := curve.DecodePoint(jsonResponse.R, true)
	if err != nil {
		return nil, fmt.Errorf("sign response: unable to decode R: %w", err)
	}

	var partialSignature partialsignature.SchnorrPartialSignature
	switch jsonResponse.Sharing {
	case "additive":
		partialSignature = partialsignature.NewSchnorrPartialSignature(s.node.info.SCHNORR.String(), jsonResponse.PlayerIndex, jsonResponse.Threshold, secretshare.AdditiveSharing, sShare, R, publicKey)
	case "shamir":
		partialSignature = partialsignature.NewSchnorrPartialSignature(s.node.info.SCHNORR.String(), jsonResponse.PlayerIndex, jsonResponse.Threshold, secretshare.ShamirSharing, sShare, R, publicKey)
	default:
		return nil, fmt.Errorf("sign response: unknown sharing type: %s", jsonResponse.Sharing)
	}

	return &SchnorrPartialSignResult{
		PresignatureID:   jsonResponse.PresignatureID,
		PartialSignature: partialSignature.Encode(),
	}, nil
}
