package tsm

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/transport"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/ec"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/partialresults/partialsignature"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/secretshare"
	"io"
	"net/http"
)

// ECDSAPartialSignResult contains a partial signature as well as the ID of the presignature used to produce it. The
// presignature ID is empty if the partial signature was generated without presignatures.
type ECDSAPartialSignResult struct {
	PresignatureID   string
	PartialSignature []byte
}

// ECDSARecoveredPrivateKey contains a raw ECDSA private key in big endian format as well as the master chain code.
type ECDSARecoveredPrivateKey struct {
	PrivateKey      []byte
	MasterChainCode []byte
}

// ECDSAWrappedKeyShare contains a wrapped (encrypted) key share and chain code as well as the corresponding public key.
type ECDSAWrappedKeyShare struct {
	WrappedKeyShare  []byte
	WrappedChainCode []byte
	PKIXPublicKey    []byte
}

// ECDSAAPI provides functionality related to ECDSA keys and signatures.
//
// # Deterministic Key Derivation
//
// The API supports HD key derivation of ECDSA keys as specified in BIP32.
// This can be done in two ways:
//
//  1. Most of the methods on ECDSAAPI only support non-hardened BIP-32 derivation, and
//     while the key itself is secret shared, each MPC node holds a complete copy of the chain code.
//     In addition, the GenerateKey() generates the master key and master chain
//     code as two independent values, and not from a seed.
//  2. If strict compliance to the BIP32 standard is required, the methods BIP32GenerateSeed(),
//     BIP32ImportSeed(), BIP32DeriveFromSeed(), BIP32DeriveFromKey(), and BIP32ConvertKey() allows you to generate
//     or import the initial seed, derive the master key and chain code from the seed exactly
//     as defined by BIP32 (and where the chain code is also secret shared), do hardened derivations,
//     and finally, to convert a key obtained by hardened derivation, into a format that can be
//     used for signing using PartialSign(), etc. The PartialSign() or a similar method lets you do
//     additional non-hardened derivations, before the signature is created.
//     These methods are not as efficient as (1), but they enable strict compliance with BIP32 and BIP44.
type ECDSAAPI interface {

	// GenerateKey instructs this player to participate in an MPC session that generates an ECDSA key.
	//
	// All players in the session must agree on threshold, curveName, and desiredKeyID.
	//
	// Input:
	//   - threshold: The security threshold for the key. Must be at least 1 and at most the total number of nodes minus
	//     one. The TSM guarantees that the key remains secure as long as at most threshold number of MPC nodes are
	//     corrupted.
	//   - curveName: The elliptic curve for the key. Must be one of "secp256k1", "P-224", "P-256", "P-384", or "P-521".
	//   - desiredKeyID (optional): A unique string of length 28, containing only ascii letters and numbers. If
	//     provided, the generated key will get this key ID.
	//
	// Output:
	//   - keyID: The ID of the new key. If desiredKeyID was provided, it will be output here.
	GenerateKey(ctx context.Context, sessionConfig *SessionConfig, threshold int, curveName string, desiredKeyID string) (keyID string, err error)

	// GeneratePresignatures instructs this player to participate in an MPC session that generates a number of
	// presignatures for an ECDSA key.
	//
	// All players in the session must agree on keyID and presignatureCount. The call blocks until all players are
	// instructed to participate in the session, or the session times out (default timeout is 10 seconds).
	GeneratePresignatures(ctx context.Context, sessionConfig *SessionConfig, keyID string, presignatureCount uint64) (presignatureIDs []string, err error)

	// Sign instructs this player to participate in an MPC session for generating an ECDSA signature.
	//
	// All players in the session must agree on keyID, derivationPath, and messageHash. The call blocks until all players are
	// instructed to participate in the session, or the session times out (default timeout is 10 seconds).
	//
	// Input:
	//   - keyID: The key to use for signing.
	//   - derivationPath (optional): Must be nil for curves other than secp256k1. If nil, the key defined by keyID is used
	//     for signing. For secp256k1, the derivationPath may optionally specify a BIP-32 chain path, and if so, signing is
	//     done using the key derived from the key defined by keyID, using the given derivation path. The derivationPath must
	//     be a non-hardened chain path of depth at most 50; i.e., derivationPath may be a list of at most 50 uint32 values,
	//     each value greater or equal to 0 and less than 2^31.
	//   - messageHash: A hash of the message to be signed. The byte length depends on the key's curve: 28 for P-224; 32
	//     bytes for secp256k1 and P-256; 48 bytes for P-384; and 64 bytes for P-521.
	//
	// Output:
	//   - signResult: The partial signature for this player. Use ECDSAFinalizeSignature to combine partial signatures
	//     into a full ECDSA signature.
	Sign(ctx context.Context, sessionConfig *SessionConfig, keyID string, derivationPath []uint32, messageHash []byte) (signResult *ECDSAPartialSignResult, err error)

	// SignWithPresignature creates a partial ECDSA signature.
	//
	// Works as Sign(), except that a presignature is consumed by SignWithPresignature(), and the presignature allows
	// this player to locally compute the partial signature without participating in any MPC session that requires
	// communication between the players.
	//
	// If presignatureID is empty, the player instead uses a random unused presignature, and its ID is returned as part
	// of the signResult.
	//
	// In order to produce a valid signature, all involved players must agree on the presignature to use.
	SignWithPresignature(ctx context.Context, keyID string, presignatureID string, derivationPath []uint32, messageHash []byte) (signResult *ECDSAPartialSignResult, err error)

	// GenerateRecoveryData instructs this player to participate in an MPC session that generates recovery data for an
	// ECDSA key.
	//
	// The recovery data consists of all the private key shares and the chain code, all encrypted under the ERS public
	// key and using the provided ersLabel as OAEP label. The recovery data also includes a zero-knowledge proof that
	// can be used to validate the recovery data without the ERS private key.
	//
	// Once all the partial recovery data have been gathered from the players, they can be combined to a single complete
	// recovery data using the method ECDSAFinalizeRecoveryData(). Later, ECDSAValidateRecoveryData() can be used to
	// validate correctness of the complete recovery data. Finally, ECDSARecoverPrivateKey() can be used to recover the
	// full private key from the complete recovery data.
	//
	// All players in the session must agree on keyID, ersPublicKey, and ersLabel. The call blocks until all players are
	// instructed to participate in the session, or the session times out (default timeout is 10 seconds).
	//
	// Input:
	//   - keyID: The ECDSA key for which to generate recovery data.
	//   - ersPublicKey: The ERS public key used to encrypt the recovery data. Must be an RSA key as the
	//     SubjectPublicKeyInfo of an ASN.1 DER encoding. The RSA key must be large enough to directly encrypt scalars
	//     using RSA-OAEP-SHA256 encrypted. A 2048-bit RSA key suffices for all currently supported curves.
	//   - ersLabel (optional): An OAEP label which can be verified by the ERS decryption service.
	//
	// Output:
	//   - partialRecoveryData: The partial recovery data for this player. Use ECDSAFinalizeRecoveryData() to combine
	//     partial recovery data into the final recovery data.
	GenerateRecoveryData(ctx context.Context, sessionConfig *SessionConfig, keyID string, ersPublicKey *rsa.PublicKey, ersLabel []byte) (partialRecoveryData []byte, err error)

	// PublicKey returns the public key corresponding to an ECDSA key in the TSM.
	//
	// CAVEAT: This returns the public key from this player, without any guarantee that other honest players have
	// successfully completed the key generation protocol and stored their share of the private key. So only use the
	// returned public key, e.g., for cryptocurrency deposit, if you have validated that the other players completed
	// the key generation protocol without failure. This ensures that they have stored their share of the private key.
	// In addition, only use the public key in your application if you trust this player. A good practice is to
	// only use the public key once the public key has been obtained from all players and the public keys were all
	// identical.
	//
	// Input:
	//   - keyID: The ID of an ECDSA key in the TSM.
	//   - derivationPath (optional): Must be nil for curves other than secp256k1. If nil, the public key defined by keyID is
	//     returned. For secp256k1, the derivationPath may optionally specify a BIP-32 derivation path, and if so, the public
	//     key returned is derived from the key defined by keyID, using the given derivation path. The derivationPath must be
	//     a non-hardened chain path of depth at most 50; i.e., derivationPath may be a list of at most 50 uint32 values,
	//     each value greater or equal to 0 and less than 2^31.
	//
	// Output:
	//   - pkixPublicKey: A public ECDSA key as the SubjectPublicKeyInfo of an ASN.1 DER encoding.
	PublicKey(ctx context.Context, keyID string, derivationPath []uint32) (pkixPublicKey []byte, err error)

	// ChainCode returns the BIP32 chain code for an ECDSA secp256k1 key.
	//
	// CAVEAT: The same caveats about using the returned chain code holds here, as for the call to PublicKey.
	//
	// Input:
	//   - keyID: The ID of a secp256k1 ECDSA key in the TSM.
	//   - chainPath (optional): If nil, the chain code for the key defined by keyID is returned.
	//     The derivationPath may optionally specify a BIP-32 derivation path, and if so, the returned chain code is
	//     derived from the key defined by keyID, using the given derivation path. The chainPath must be a non-hardened
	//     chain path of depth at most 50; i.e., derivationPath may be a list of at most 50 uint32 values, each value greater
	//     or equal to 0 and less than 2^31.
	ChainCode(ctx context.Context, keyID string, derivationPath []uint32) (chainCode []byte, err error)

	// Reshare instructs this player to participate in an MPC session that refreshes the secret sharing of an ECDSA key.
	//
	// All players in the session must agree on the keyID. The call blocks until all players are instructed to
	// participate in the session, or the session times out (default timeout is 10 seconds).
	//
	// The ECDSA key remains unchanged by this operation, but the secret sharing of the key will be replaced with a new
	// random and independent secret sharing of the same key.
	//
	// CAVEAT: Reshare() invalidates all existing key shares of the key, including shares that are kept in a backup.
	//
	// Reshare() automatically deletes any existing presignatures for the key.
	//
	// If the operation fails for some reason, it should be retried until it succeeds. After this operation is called
	// for the first time and until it succeeds, other operations involving the same key might fail.
	Reshare(ctx context.Context, sessionConfig *SessionConfig, keyID string) error

	// CopyKey instructs this player to participate in an MPC session that creates a copy of an ECDSA key. The copy will
	// represent the same key, but with a new random and independent secret sharing. The copy will be saved under a new
	// key ID and the existing key will not be affected.
	//
	// It's possible to change the number of players and threshold for the copy.
	//
	// Input:
	//   - keyID: The ID of an ECDSA key in the TSM. Must be empty if this player does not hold an existing key share.
	//   - curveName: The elliptic curve for the key. Must be empty if this player holds an existing key share, otherwise
	//     it must be one of Must be one of "secp256k1", "P-224", "P-256", "P-384", or "P-521".
	//   - newThreshold: The security threshold for the key copy. Must be at least 1 and at most the total number of
	//     nodes minus one.
	//   - desiredKeyID (optional): A unique string of length 28, containing only ASCII letters and numbers. If provided,
	//     the generated key will get this key ID.
	//
	// Output:
	//   - keyID: The ID of the key copy. If desiredKeyID was provided, it will be output here.
	CopyKey(ctx context.Context, sessionConfig *SessionConfig, keyID string, curveName string, newThreshold int, desiredKeyID string) (newKeyID string, err error)

	// BackupKeyShare returns an unprotected backup of a key share.
	//
	// This is intended for backup of a key share on a mobile phone. The backup can later be used to restore the key
	// share using RestoreKeyShare().
	//
	// BackupShare() only works if explicitly enabled in the MPC node configuration.
	//
	// CAVEAT: The exported backup is not protected, and it is up to the caller to add protection to the backup to
	// prevent the key share from being leaked.
	//
	// Input:
	//   - keyID: The ID of an existing ECDSA key in the TSM.
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
	// All players in the session must agree on keyID and derivationPath. The call blocks until all players are instructed to
	// participate in the session, or the session times out (default timeout is 10 seconds).
	//
	// The public key and chain code as well as a share of the private key is exported to each player. The exported
	// private key share and chain code are encrypted under the wrapping key provided to that player.
	//
	// The MPC session generates a new, independent secret sharing of the key and uses the new shares for export.
	// The secret sharing of the key in the TSM is not changed, and the new sharing is only used for this export,
	//
	// If a derivationPath is provided, the exported key shares will be shares of a key derived from the key defined by
	// keyID, using the provided derivationPath.
	//
	// Each player is configured with a whitelist of wrapping keys and only accepts to export if the provided wrapping
	// key matches the whitelist.
	//
	// Input:
	//   - keyID: The ID of an existing ECDSA key in the TSM.
	//   - derivationPath (optional): Must be a non-hardened chain path of depth at most 50; i.e., derivationPath may be a list of
	//     at most 50 uint32 values, each value greater or equal to 0 and less than 2^31.
	//   - wrappingKey: The wrapping key used to encrypt the key share exported to the player. Must be provided as
	//     SubjectPublicKeyInfo in an ASN.1 DER encoding. The wrapping key of a target TSM can be obtained by
	//     WrappingKey().
	//
	// Output:
	//   - wrappedKeyShare: The wrapped key share and chain code exported to this player. The key share also contains
	//     the public key corresponding to the exported private key shares.
	ExportKeyShares(ctx context.Context, sessionConfig *SessionConfig, keyID string, derivationPath []uint32, wrappingKey []byte) (wrappedKeyShare *ECDSAWrappedKeyShare, err error)

	// ImportKeyShares instructs the player to participate in an MPC session that imports key shares of an ECDSA key.
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
	// If you instead want to import a private ECDSA key from somewhere else, you may want to use the helper functions
	// tsmutils.ShamirSecretShare() to split the key into shares, and tsmutils.Wrap() to wrap each share with the
	// wrapping keys obtained from calls to WrappingKey() on each of the players.
	//
	// Input:
	//   - threshold: The security threshold for the imported key.
	//   - wrappedKeyShare: The key share for this player, wrapped using the player's wrapping key, which can be
	//     obtained by WrappingKey().
	//   - wrappedChainCode (optional): The chain code for the key, wrapped under the player's wrapping key, which can
	//     be obtained by WrappingKey(). If nil, a random chain code will be generated.
	//   - pkixPublicKey: The public key corresponding to the imported key shares, as SubjectPublicKeyInfo of an ASN.1
	//     DER encoding. The public key is used to validate the imported shares; the import session fails if the
	//     imported shares does not match the provided pkixPublicKey.
	//
	// Output:
	//   - keyID: The ID of the imported key.
	ImportKeyShares(ctx context.Context, sessionConfig *SessionConfig, threshold int, wrappedKeyShare []byte, wrappedChainCode []byte, pkixPublicKey []byte, desiredKeyID string) (keyID string, err error)

	// BIP32GenerateSeed instructs the player to participate in an MPC session that generates a new BIP32 seed.
	//
	// All players in the session must agree on threshold. The call blocks until all players are instructed to
	// participate in the session, or the session times out (default timeout is 10 seconds).
	//
	// Input:
	//   - threshold: The security threshold of the seed. Must be between one and number of players - 1.
	//     The seed will remain secure even if up to threshold of the players are corrupted.
	//
	// Output:
	//   - seedID: The ID of the generated BIP32 seed.
	BIP32GenerateSeed(ctx context.Context, sessionConfig *SessionConfig, threshold int) (seedID string, err error)

	// BIP32DeriveFromSeed instructs the player to participate in an MPC session that derives a master key and master
	// chain code from a BIP32 seed.
	//
	// All players in the session must agree on seedID. The call blocks until all players are instructed to
	// participate in the session, or the session times out (default timeout is 10 seconds).
	//
	// The derived master key can be used to derive another hardened key using BIP32DeriveFromKey(),
	// or it can be converted to a signing key using BIP32ConvertKey(), which can be used to sign (possible applying
	// additional non-hardened derivations).
	//
	// Input:
	//   - seedID: The ID of the seed, as output by BIP32GenerateSeed() or BIP32ImportSeed().
	//
	// Output:
	//   - bip32KeyID: The ID of the derived master key.
	BIP32DeriveFromSeed(ctx context.Context, sessionConfig *SessionConfig, seedID string) (bip32KeyID string, err error)

	// BIP32DeriveFromKey instructs the player to participate in an MPC session that derives a BIP32 child key from a
	// parent key.
	//
	// All players in the session must agree on parentKeyID and derivationPathElement. The call blocks until all players are
	// instructed to participate in the session, or the session times out (default timeout is 10 seconds).
	//
	// The derived key can be used to derive another hardened key using BIP32DeriveFromKey(), or it can be converted to
	// a signing key using BIP32ConvertKey(), which can be used to sign (possible applying additional non-hardened
	// derivations).
	//
	// Input:
	//   - parentKeyID: The ID of the parent key, as output from BIP32DeriveFromSeed() or BIP32DeriveFromKey().
	//   - derivationPathElement: The derivation path element to use for the derivation. Must specify a hardened derivation, i.e.,
	//     the most significant bit must be set. So this must be an integer ranging from 0x80000000 to 0xFFFFFFFF.
	//
	// Output:
	//   - childKeyID: The ID of the generated child key.
	BIP32DeriveFromKey(ctx context.Context, sessionConfig *SessionConfig, parentKeyID string, derivationPathElement uint32) (childKeyID string, err error)

	// BIP32ConvertKey instructs the player to particiapte in an MPC session that converts a BIP32 key to a secp256k1
	// key that can be used for signing.
	//
	// All players in the session must agree on bip32KeyID. The call blocks until all players are instructed to
	// participate in the session, or the session times out (default timeout is 10 seconds).
	//
	// Input:
	//   - bip32KeyID: The ID of the parent key, e.g., as output from BIP32DeriveFromSeed() or BIP32DeriveFromKey().
	//
	// Output:
	//   - ecKeyID: The ID of the converted key. This key can be used for signing, e.g., using Sign().
	BIP32ConvertKey(ctx context.Context, sessionConfig *SessionConfig, bip32KeyID string) (keyID string, err error)

	// BIP32ExportSeed instructs the player to participate in an MPC session that exports encrypted shares of a BIP32
	// seed.
	//
	// All players in the session must agree on seedID. The call blocks until all players are instructed to
	// participate in the session, or the session times out (default timeout is 10 seconds).
	//
	// The MPC session will output one xor (exclusive or) share to each player along with a witness. Before returning
	// the share, the player will encrypt the share using the provided wrapping key.
	//
	// The exported xor sharing is independent of the internal sharing of the seed in the TSM.
	//
	// The export operation will only work if BIP32 seed export is explicitly enabled in the player configuration,
	// and each player has a whitelist of wrapping keys and only allows export of shares that are wrapped with keys in
	// this whitelist.
	//
	// Input:
	//   - seedID: The ID of an existing BIP32 seed in the TSM, as output by BIP32GenerateSeed() or BIP32ImportSeed().
	//   - wrappingKey: The wrapping key that this player should use to encrypt the exported share. Must be provided as
	//     a SubjectPublicKeyInfo, in ASN.1 DER encoding.
	//
	// Output:
	//   - wrappedSeedShare: The wrapped share is an encryption of a seed share that is between 16 and 64 bytes,
	//     depending on the length of the seed that is being exported. The encryption is RSA-OAEP-SHA256.
	//   - seedWitness: A witness of the seed, computed as
	//     witness := sha512.Sum512(append([]byte("Exported Share"), seed...))
	BIP32ExportSeed(ctx context.Context, sessionConfig *SessionConfig, seedID string, wrappingKey []byte) (seed *BIP32Seed, err error)

	// BIP32ImportSeed instructs the player to participate in an MPC session that imports encrypted shares of a BIP32
	// seed.
	//
	// All players in the session must agree on threshold, seedWitness, and the length of the seed shares. The call
	// blocks until all players are instructed to participate in the session, or the session times out (default timeout
	// is 10 seconds).
	//
	// The imported seed will be defined as the byte-wise xor (exclusive or) of the provided shares.
	//
	// The share provided to a player must be encrypted (wrapped) under that player's wrapping key, which can be
	// obtained by calling WrappingKey().
	//
	// The final internal sharing of the seed will be independent of the xor sharing provided here.
	//
	// If a witness is provided, the session will abort unless the imported seed is consistent with the witness.
	//
	// To transfer a seed from a source TSM to a target TSM, you first call WrappingKey() on the players in the target
	// TSM. Then call BIP32ExportSeed() on each of the players of the source TSM, providing the wrapping keys. The
	// output from ExportKeyShares() on the source TSM can then be used as input to ImportKeyShares() on the target TSM.
	//
	// If you instead want to import a BIP32 seed from somewhere else, you must first split the seed into seed shares
	// such that the byte-wise xor (exclusive or) of the shares equal the seed. And you must optionally compute a
	// witness of the seed as witness := sha512.Sum512(append([]byte("Exported Share"), seed...)).
	// Then each seed share must be wrapped using RSA-OAEP-SHA256. You may use the tsmutils.Wrap() for this.
	//
	// Input:
	//   - threshold: The security threshold to use for the imported seed. Must be between 1 and number of players - 1.
	//     The seed will be protected if up to threshold of the players are corrupted.
	//   - wrappedSeedShare: The share imported to this player, encrypted under the player's wrapping key. The share
	//     must be between 16 and 64 bytes, 32 bytes recommended.
	//   - seedWitness (optional): A witness for the seed, on the form
	//     witness := sha512.Sum512(append([]byte("Exported Share"), seed...)).
	//
	// Output:
	//   - seedID: The ID of the imported seed.
	BIP32ImportSeed(ctx context.Context, sessionConfig *SessionConfig, threshold int, seed *BIP32Seed) (seedID string, err error)

	// BIP32Info returns information about a key or seed.
	//
	// Input:
	//   - keyID: The ID of an existing BIP32 seed, BIP32 key or ECDSA signing key in the TSM.
	//
	// Output:
	//   - info.KeyType: The type of the key, one of these "BIP32Seed", "BIP32Key", "ECKey". If BIP32Seed, you can use the
	//     keyID as input to BIP32DeriveFromSeed(). If BIP32Key, you can use keyID as input to BIP32DeriveFromKey or
	//     BIP32ConvertKey(). If ECKey, you can use keyID as input to the remaining methods, such as Sign().
	//   - info.DerivationPath: Is nil except for a BIP32Key, in which case it is the derivation path for the given key (nil
	//     if master key).
	//   - info.ParentKeyID: Is nil for a BIP32Seed. For a BIP32Key it points to the parent BIP32Key (or BIP32Seed, if it is
	//     the master key). For an ECKey, parentKeyID is the keyID of the BIP32Key from which the key was converted, or
	//     nil, if the ECKey was created in another way, e.g., directly via Keygen().
	BIP32Info(ctx context.Context, keyID string) (info *BIP32Info, err error)
}

type BIP32Seed struct {
	WrappedSeedShare, SeedWitness []byte
}

type BIP32Info struct {
	KeyType        string
	DerivationPath []uint32
	ParentKeyID    string
}

type ecdsaService struct {
	*node
}

func (e *ecdsaService) GenerateKey(ctx context.Context, sessionConfig *SessionConfig, threshold int, curveName string, desiredKeyID string) (keyID string, err error) {
	if desiredKeyID != "" {
		if err = validateKeyID(desiredKeyID); err != nil {
			return "", toTSMError(err, ErrInvalidInput)
		}
	}

	res, err := e.call(ctx, http.MethodPost, "/ecdsa/keys", sessionConfig, e.sendAuthenticatedRequest,
		func() interface{} {
			return transport.ECDSAKeyGenRequest{
				Threshold: threshold,
				Curve:     curveName,
				KeyID:     desiredKeyID,
			}
		})
	if err != nil {
		return "", toTSMError(err, ErrOperationFailed)
	}

	var jsonResponse transport.ECDSAKeyGenResponse
	err = unmarshalJSON(res, &jsonResponse)
	if err != nil {
		return "", err
	}
	return jsonResponse.KeyID, nil
}

func (e *ecdsaService) GeneratePresignatures(ctx context.Context, sessionConfig *SessionConfig, keyID string, presignatureCount uint64) (presignatureIDs []string, err error) {
	if err = validateKeyID(keyID); err != nil {
		return nil, toTSMError(err, ErrInvalidInput)
	}

	res, err := e.call(ctx, http.MethodPost, fmt.Sprintf("/ecdsa/keys/%s/%d/presiggen", keyID, presignatureCount), sessionConfig, e.sendAuthenticatedRequest, nil)
	if err != nil {
		return nil, toTSMError(err, ErrOperationFailed)
	}

	var jsonResponse transport.ECDSAPresigGenResponse
	err = unmarshalJSON(res, &jsonResponse)
	if err != nil {
		return nil, toTSMError(err, ErrOperationFailed)
	}

	if uint64(len(jsonResponse.IDs)) != presignatureCount {
		return nil, toTSMError(errors.New("invalid number of presignature IDs returned"), ErrOperationFailed)
	}

	return jsonResponse.IDs, nil
}

func (e *ecdsaService) Sign(ctx context.Context, sessionConfig *SessionConfig, keyID string, derivationPath []uint32, messageHash []byte) (signResult *ECDSAPartialSignResult, err error) {
	if err = validateKeyID(keyID); err != nil {
		return nil, toTSMError(err, ErrInvalidInput)
	}

	res, err := e.call(ctx, http.MethodPost, fmt.Sprintf("/ecdsa/keys/%s/sign", keyID), sessionConfig, e.sendAuthenticatedRequest,
		func() interface{} {
			return transport.ECDSASignRequest{
				ChainPath:   derivationPath,
				MessageHash: messageHash,
			}
		})
	if err != nil {
		return nil, toTSMError(err, ErrOperationFailed)
	}

	signResult, err = e.parseSignResponse(res)
	if err != nil {
		return nil, toTSMError(err, ErrOperationFailed)
	}

	return signResult, nil
}

func (e *ecdsaService) SignWithPresignature(ctx context.Context, keyID string, presignatureID string, derivationPath []uint32, messageHash []byte) (signResult *ECDSAPartialSignResult, err error) {
	if err = validateKeyID(keyID); err != nil {
		return nil, toTSMError(err, ErrInvalidInput)
	}

	res, err := e.call(ctx, http.MethodPost, fmt.Sprintf("/ecdsa/keys/%s/signwithpresig", keyID), &SessionConfig{}, e.sendAuthenticatedRequest,
		func() interface{} {
			return transport.ECDSASignWithPresigRequest{
				ChainPath:      derivationPath,
				MessageHash:    messageHash,
				PresignatureID: presignatureID,
			}
		})
	if err != nil {
		return nil, toTSMError(err, ErrOperationFailed)
	}

	signResult, err = e.parseSignResponse(res)
	if err != nil {
		return nil, toTSMError(err, ErrOperationFailed)
	}

	return signResult, nil
}

func (e *ecdsaService) GenerateRecoveryData(ctx context.Context, sessionConfig *SessionConfig, keyID string, ersPublicKey *rsa.PublicKey, ersLabel []byte) (partialRecoveryData []byte, err error) {
	if err = validateKeyID(keyID); err != nil {
		return nil, toTSMError(err, ErrInvalidInput)
	}

	res, err := e.call(ctx, http.MethodPost, fmt.Sprintf("/ecdsa/keys/%s/recoveryinfo", keyID), sessionConfig, e.sendAuthenticatedRequest,
		func() interface{} {
			return transport.ECDSARecoveryInfoRequest{
				ERSPublicKey:      *ersPublicKey,
				Label:             ersLabel,
				OutputPlayerIndex: -1,
			}
		})
	if err != nil {
		return nil, toTSMError(err, ErrOperationFailed)
	}

	var jsonResponse transport.ECDSARecoveryInfoResponse
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

func (e *ecdsaService) PublicKey(ctx context.Context, keyID string, derivationPath []uint32) (pkixPublicKey []byte, err error) {
	if err = validateKeyID(keyID); err != nil {
		return nil, toTSMError(err, ErrInvalidInput)
	}

	res, err := e.call(ctx, http.MethodPost, fmt.Sprintf("/ecdsa/keys/%s/publickey", keyID), &SessionConfig{}, e.sendAuthenticatedRequest,
		func() interface{} {
			return transport.ECDSAPublicKeyRequest{
				ChainPath: derivationPath,
			}
		})
	if err != nil {
		return nil, toTSMError(err, ErrOperationFailed)
	}

	var jsonResponse transport.ECDSAPublicKeyResponse
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

	pkixPublicKey, err = ecdsaPointToPKIXPublicKey(ecPublicKey)
	if err != nil {
		return nil, toTSMError(fmt.Errorf("public key: unable to encode public key: %w", err), ErrOperationFailed)
	}

	return pkixPublicKey, nil
}

func (e *ecdsaService) ChainCode(ctx context.Context, keyID string, derivationPath []uint32) (chainCode []byte, err error) {
	if err = validateKeyID(keyID); err != nil {
		return nil, toTSMError(err, ErrInvalidInput)
	}

	response, err := e.call(ctx, http.MethodPost, fmt.Sprintf("/ecdsa/keys/%s/chaincode", keyID), &SessionConfig{}, e.sendAuthenticatedRequest,
		func() interface{} {
			return transport.ECDSAChainCodeRequest{
				ChainPath: derivationPath,
			}
		})
	if err != nil {
		return nil, toTSMError(err, ErrInvalidInput)
	}

	var jsonResponse transport.ECDSAChainCodeResponse
	err = unmarshalJSON(response, &jsonResponse)
	if err != nil {
		return nil, toTSMError(err, ErrOperationFailed)
	}

	return jsonResponse.ChainCode, nil
}

func (e *ecdsaService) Reshare(ctx context.Context, sessionConfig *SessionConfig, keyID string) error {
	if err := validateKeyID(keyID); err != nil {
		return toTSMError(err, ErrInvalidInput)
	}

	_, err := e.call(ctx, http.MethodPost, fmt.Sprintf("/ecdsa/keys/%s/reshare", keyID), sessionConfig, e.sendAuthenticatedRequest, nil)
	if err != nil {
		return toTSMError(err, ErrOperationFailed)
	}
	return nil
}

func (e *ecdsaService) CopyKey(ctx context.Context, sessionConfig *SessionConfig, keyID string, curveName string, newThreshold int, desiredKeyID string) (newKeyID string, err error) {
	if keyID != "" {
		if err := validateKeyID(keyID); err != nil {
			return "", toTSMError(err, ErrInvalidInput)
		}
	}
	if desiredKeyID != "" {
		if err = validateKeyID(desiredKeyID); err != nil {
			return "", toTSMError(err, ErrInvalidInput)
		}
	}
	if keyID == "" {
		keyID = "_"
	}

	res, err := e.call(ctx, http.MethodPost, fmt.Sprintf("/ecdsa/keys/%s/keycopy", keyID), sessionConfig, e.sendAuthenticatedRequest,
		func() interface{} {
			return transport.ECDSAKeyCopyRequest{
				Threshold: newThreshold,
				Curve:     curveName,
				KeyID:     desiredKeyID,
			}
		})
	if err != nil {
		return "", toTSMError(err, ErrOperationFailed)
	}

	var jsonResponse transport.ECDSAKeyCopyResponse
	err = unmarshalJSON(res, &jsonResponse)
	if err != nil {
		return "", err
	}
	return jsonResponse.KeyID, nil
}

func (e *ecdsaService) BackupKeyShare(ctx context.Context, keyID string) (keyShareBackup []byte, err error) {
	if err = validateKeyID(keyID); err != nil {
		return nil, toTSMError(err, ErrInvalidInput)
	}

	response, err := e.call(ctx, http.MethodGet, fmt.Sprintf("/ecdsa/keys/%s/backupshare", keyID), &SessionConfig{}, e.sendAuthenticatedRequest, nil)
	if err != nil {
		return nil, toTSMError(err, ErrInvalidInput)
	}

	var jsonResponse transport.ECDSABackupResponse
	err = unmarshalJSON(response, &jsonResponse)
	if err != nil {
		return nil, toTSMError(err, ErrOperationFailed)
	}

	return jsonResponse.ShareBackup, nil
}

func (e *ecdsaService) RestoreKeyShare(ctx context.Context, keyShareBackup []byte) (keyID string, err error) {
	response, err := e.call(ctx, http.MethodPost, "/ecdsa/keys/restoreshare", &SessionConfig{}, e.sendAuthenticatedRequest,
		func() interface{} {
			return transport.ECDSARestoreRequest{
				ShareBackup: keyShareBackup,
			}
		})
	if err != nil {
		return "", toTSMError(err, ErrInvalidInput)
	}

	var jsonResponse transport.ECDSARestoreResponse
	err = unmarshalJSON(response, &jsonResponse)
	if err != nil {
		return "", toTSMError(err, ErrOperationFailed)
	}

	return jsonResponse.KeyID, nil
}

func (e *ecdsaService) ExportKeyShares(ctx context.Context, sessionConfig *SessionConfig, keyID string, derivationPath []uint32, wrappingKey []byte) (wrappedKeyShare *ECDSAWrappedKeyShare, err error) {
	if err = validateKeyID(keyID); err != nil {
		return nil, toTSMError(err, ErrInvalidInput)
	}

	res, err := e.call(ctx, http.MethodPost, fmt.Sprintf("/ecdsa/keys/%s/export", keyID), sessionConfig, e.sendAuthenticatedRequest,
		func() interface{} {
			return transport.ECDSAKeyExportRequest{
				WrappingKey: wrappingKey,
				ChainPath:   derivationPath,
			}
		})
	if err != nil {
		return nil, toTSMError(err, ErrOperationFailed)
	}

	var jsonResponse transport.ECDSAKeyExportResponse
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

	pkixPublicKey, err := ecdsaPointToPKIXPublicKey(ecPublicKey)
	if err != nil {
		return nil, toTSMError(fmt.Errorf("export key shares: unable to encode public key: %w", err), ErrOperationFailed)
	}

	return &ECDSAWrappedKeyShare{
		WrappedKeyShare:  jsonResponse.EncryptedKeyShare,
		WrappedChainCode: jsonResponse.EncryptedChainCode,
		PKIXPublicKey:    pkixPublicKey,
	}, nil
}

func (e *ecdsaService) ImportKeyShares(ctx context.Context, sessionConfig *SessionConfig, threshold int, wrappedKeyShare []byte, wrappedChainCode []byte, pkixPublicKey []byte, desiredKeyID string) (keyID string, err error) {
	if desiredKeyID != "" {
		if err = validateKeyID(desiredKeyID); err != nil {
			return "", toTSMError(err, ErrInvalidInput)
		}
	}

	publicKey, err := ecdsaPKIXPublicKeyToPoint(pkixPublicKey)
	if err != nil {
		return "", toTSMError(fmt.Errorf("import key shares: unable to decode public key: %w", err), ErrInvalidInput)
	}

	res, err := e.call(ctx, http.MethodPost, "/ecdsa/keys/import", sessionConfig, e.sendAuthenticatedRequest,
		func() interface{} {
			return transport.ECDSAKeyImportRequest{
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

	var jsonResponse transport.ECDSAKeyImportResponse
	err = unmarshalJSON(res, &jsonResponse)
	if err != nil {
		return "", err
	}

	return jsonResponse.KeyID, nil
}

func (e *ecdsaService) BIP32GenerateSeed(ctx context.Context, sessionConfig *SessionConfig, threshold int) (seedID string, err error) {
	res, err := e.call(ctx, http.MethodPost, "/ecdsa/keys/bip32/generateseed", sessionConfig, e.sendAuthenticatedRequest,
		func() interface{} {
			return transport.ECDSABIP32GenSeedRequest{
				Threshold: threshold,
			}
		})
	if err != nil {
		return "", toTSMError(err, ErrOperationFailed)
	}

	var jsonResponse transport.ECDSABIP32GenSeedResponse
	err = unmarshalJSON(res, &jsonResponse)
	if err != nil {
		return "", err
	}
	return jsonResponse.SeedID, nil
}

func (e *ecdsaService) BIP32DeriveFromSeed(ctx context.Context, sessionConfig *SessionConfig, seedID string) (bip32KeyID string, err error) {
	if err = validateKeyID(seedID); err != nil {
		return "", toTSMError(err, ErrInvalidInput)
	}

	res, err := e.call(ctx, http.MethodPost, fmt.Sprintf("/ecdsa/keys/bip32/%s/derivefromseed", seedID), sessionConfig, e.sendAuthenticatedRequest,
		func() interface{} {
			return transport.ECDSABIP32DeriveFromSeedRequest{
				SeedID: seedID,
			}
		})
	if err != nil {
		return "", toTSMError(err, ErrOperationFailed)
	}

	var jsonResponse transport.ECDSABIP32DeriveFromSeedResponse
	err = unmarshalJSON(res, &jsonResponse)
	if err != nil {
		return "", err
	}
	return jsonResponse.KeyID, nil
}

func (e *ecdsaService) BIP32DeriveFromKey(ctx context.Context, sessionConfig *SessionConfig, parentKeyID string, derivationPathElement uint32) (childKeyID string, err error) {
	if err = validateKeyID(parentKeyID); err != nil {
		return "", toTSMError(err, ErrInvalidInput)
	}

	res, err := e.call(ctx, http.MethodPost, fmt.Sprintf("/ecdsa/keys/bip32/%s/derivefromkey/%d", parentKeyID, derivationPathElement), sessionConfig, e.sendAuthenticatedRequest,
		func() interface{} {
			return transport.ECDSABIP32DeriveFromKeyRequest{
				ParentKeyID: parentKeyID,
			}
		})
	if err != nil {
		return "", toTSMError(err, ErrOperationFailed)
	}

	var jsonResponse transport.ECDSABIP32DeriveFromKeyResponse
	err = unmarshalJSON(res, &jsonResponse)
	if err != nil {
		return "", err
	}
	return jsonResponse.ChildKeyID, nil
}

func (e *ecdsaService) BIP32ConvertKey(ctx context.Context, sessionConfig *SessionConfig, bip32KeyID string) (keyID string, err error) {
	if err = validateKeyID(bip32KeyID); err != nil {
		return "", toTSMError(err, ErrInvalidInput)
	}

	res, err := e.call(ctx, http.MethodPost, fmt.Sprintf("/ecdsa/keys/bip32/%s/convertkey", bip32KeyID), sessionConfig, e.sendAuthenticatedRequest,
		func() interface{} {
			return transport.ECDSABIP32ConvertKeyRequest{
				KeyID: bip32KeyID,
			}
		})
	if err != nil {
		return "", toTSMError(err, ErrOperationFailed)
	}

	var jsonResponse transport.ECDSABIP32ConvertKeyResponse
	err = unmarshalJSON(res, &jsonResponse)
	if err != nil {
		return "", err
	}
	return jsonResponse.KeyID, nil
}

func (e *ecdsaService) BIP32ImportSeed(ctx context.Context, sessionConfig *SessionConfig, threshold int, seed *BIP32Seed) (seedID string, err error) {
	res, err := e.call(ctx, http.MethodPost, fmt.Sprintf("/ecdsa/keys/bip32/importseed"), sessionConfig, e.sendAuthenticatedRequest,
		func() interface{} {
			return transport.ECDSABIP32ImportSeedRequest{
				Threshold:   threshold,
				SeedShare:   seed.WrappedSeedShare,
				SeedWitness: seed.SeedWitness,
			}
		})
	if err != nil {
		return "", toTSMError(err, ErrOperationFailed)
	}

	var jsonResponse transport.ECDSABIP32ImportSeedResponse
	err = unmarshalJSON(res, &jsonResponse)
	if err != nil {
		return "", err
	}
	return jsonResponse.SeedID, nil
}

func (e *ecdsaService) BIP32ExportSeed(ctx context.Context, sessionConfig *SessionConfig, seedID string, wrappingKey []byte) (seed *BIP32Seed, err error) {
	if err = validateKeyID(seedID); err != nil {
		return nil, toTSMError(err, ErrInvalidInput)
	}

	res, err := e.call(ctx, http.MethodPost, fmt.Sprintf("/ecdsa/keys/bip32/%s/exportseed", seedID), sessionConfig, e.sendAuthenticatedRequest,
		func() interface{} {
			return transport.ECDSABIP32ExportSeedRequest{
				WrappingKey: wrappingKey,
			}
		})
	if err != nil {
		return nil, toTSMError(err, ErrOperationFailed)
	}

	var jsonResponse transport.ECDSABIP32ExportSeedResponse
	err = unmarshalJSON(res, &jsonResponse)
	if err != nil {
		return nil, err
	}
	return &BIP32Seed{
		WrappedSeedShare: jsonResponse.EncryptedSeedShare,
		SeedWitness:      jsonResponse.SeedWitness,
	}, nil
}

func (e *ecdsaService) BIP32Info(ctx context.Context, keyID string) (info *BIP32Info, err error) {
	if err = validateKeyID(keyID); err != nil {
		return nil, toTSMError(err, ErrInvalidInput)
	}

	res, err := e.call(ctx, http.MethodPost, fmt.Sprintf("/ecdsa/keys/bip32/%s/info", keyID), &SessionConfig{}, e.sendAuthenticatedRequest,
		func() interface{} {
			return nil
		})
	if err != nil {
		return nil, toTSMError(err, ErrOperationFailed)
	}

	var jsonResponse transport.ECDSABIP32InfoResponse
	err = unmarshalJSON(res, &jsonResponse)
	if err != nil {
		return nil, err
	}
	return &BIP32Info{
		KeyType:        jsonResponse.KeyType,
		DerivationPath: jsonResponse.ChainPath,
		ParentKeyID:    jsonResponse.ParentKeyID,
	}, nil
}

func (e *ecdsaService) parseSignResponse(response io.Reader) (*ECDSAPartialSignResult, error) {
	var jsonResponse transport.ECDSASignResponse
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

	var partialSignature partialsignature.ECDSAPartialSignature
	switch jsonResponse.Sharing {
	case "additive":
		partialSignature = partialsignature.NewECDSAPartialSignature(e.node.info.ECDSA.String(), jsonResponse.PlayerIndex, jsonResponse.Threshold, secretshare.AdditiveSharing, sShare, R, publicKey)
	case "shamir":
		partialSignature = partialsignature.NewECDSAPartialSignature(e.node.info.ECDSA.String(), jsonResponse.PlayerIndex, jsonResponse.Threshold, secretshare.ShamirSharing, sShare, R, publicKey)
	default:
		return nil, fmt.Errorf("sign response: unknown sharing type: %s", jsonResponse.Sharing)
	}

	return &ECDSAPartialSignResult{
		PresignatureID:   jsonResponse.PresignatureID,
		PartialSignature: partialSignature.Encode(),
	}, nil
}
