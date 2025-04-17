package ers

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"sync"
)

import (
	"bytes"
	"crypto/sha256"
	"reflect"

	"golang.org/x/sync/errgroup"

	"github.com/palisadeinc/mpc-recovery/math"
)

// This is data contained in each player's partial recovery data and on which the players should agree.
type commonDataV2 struct {
	Version                     string
	PlayerCount                 int
	Threshold                   int
	SharingType                 string
	KeyShareCommitments         [][]byte
	CurveName                   string
	PublicKeyBytes              []byte
	AuxDataPublic               []byte
	AuxDataPrivateEncrypted     []byte
	AuxDataWrappedEncryptionKey []byte
	Nonce                       []byte

	Curve     math.Curve
	PublicKey math.Point
}

func validateJSONV2(ersPublicKey rsa.PublicKey, label []byte, publicKeyBytes, recoveryDataJSON []byte) error {

	var recoveryData recoveryDataV2
	err := json.Unmarshal(recoveryDataJSON, &recoveryData)
	if err != nil {
		return err
	}

	if len(recoveryData.PartialRecoveryData) == 0 {
		return fmt.Errorf("invalid recovery data: no partial recovery data")
	}

	if recoveryData.PartialRecoveryData[0].SharingType == multiplicative {
		return fmt.Errorf("validation of multiplicative sharing not supported")
	}

	_, err = validateV2(recoveryData, &ersPublicKey, label, publicKeyBytes)
	if err != nil {
		return err
	}

	return nil
}

// Validates recovery data, including zero-knowledge proofs.
// Returns an error if not valid; otherwise returns recover data key parts required for recovery of key shares.
// If called without ersPublicKey, ersLabel, and externalPublicKeyBytes, the basic structure of the partial recovery
// data is validated, but not the zero-knowledge proofs.
func validateV2(recoveryData recoveryDataV2, ersPublicKey *rsa.PublicKey, ersLabel []byte, externalPublicKeyBytes []byte) (map[int]recoveryDataKeyPart, error) {
	recoveryInfos := recoveryData.PartialRecoveryData

	common, err := validateAgreementOnPublicValuesV2(recoveryInfos)
	if err != nil {
		return nil, fmt.Errorf("invalid recovery data: %w", err)
	}

	// Check that we got partial recovery info from all players

	playerIndices := map[int]bool{}
	for i := 0; i < len(recoveryInfos); i++ {
		playerIndices[recoveryInfos[i].PlayerIndex] = true
	}
	for i := 0; i < len(recoveryInfos); i++ {
		if !playerIndices[i] {
			return nil, fmt.Errorf("missing recovery data for player: %d", i)
		}
	}

	if common.Version != RecoveryDataVersion2 {
		return nil, fmt.Errorf("recovery data version mismatch: expected %s but was %s", RecoveryDataVersion2, common.Version)
	}

	if len(recoveryInfos) != common.PlayerCount {
		return nil, fmt.Errorf("there are %d players but %d recovery infos", recoveryInfos[0].PlayerCount, len(recoveryInfos))
	}

	if len(recoveryInfos) <= common.Threshold {
		return nil, fmt.Errorf("not enough recovery infos (%d) for the threshold: %d", len(recoveryInfos), recoveryInfos[0].Threshold)
	}

	switch common.CurveName {
	case "secp256k1", "P-224", "P-256", "P-384", "P-521", "ED-25519", "ED-448":
		// ok
	default:
		return nil, fmt.Errorf("unsupported public key curve: %s", common.CurveName)
	}

	switch common.SharingType {
	case additive, shamir:
		// ok
	case multiplicative:
		// We only support validation of multiplicative sharings in the case where we know that
		// at least one of the nodes is honest; to validate multiplicative sharings against an external
		// public key alone would require additional zero knowledge proofs.
		if externalPublicKeyBytes != nil {
			return nil, fmt.Errorf("validating multiplicative sharing with external public key not supported")
		}
	default:
		return nil, fmt.Errorf("unsupported sharing type: %s", common.SharingType)
	}

	// If external public key is provided, validate that it matches the public key contained in the recovery data

	if externalPublicKeyBytes != nil {
		externalPublicKey, err := getPublicKeyFromBytes(common.Curve, externalPublicKeyBytes)
		if err != nil {
			return nil, err
		}
		if !common.PublicKey.Equals(externalPublicKey) {
			return nil, fmt.Errorf("mismatch between provided public key and public key contained in recovery data")
		}

	}

	// Validate the individual zero-knowledge proofs from each player

	keyParts := make(map[int]recoveryDataKeyPart)
	keyPartsLock := sync.Mutex{}

	var eg errgroup.Group
	for _, recoveryInfo := range recoveryInfos {
		recoveryInfo := recoveryInfo
		eg.Go(func() error {
			keyPart, err := validateZeroKnowledgeProofV2(common, ersPublicKey, ersLabel, recoveryInfo)
			if err != nil {
				return err
			}

			keyPartsLock.Lock()
			keyParts[recoveryInfo.PlayerIndex] = keyPart
			keyPartsLock.Unlock()

			return nil
		})
	}
	err = eg.Wait()
	if err != nil {
		return nil, err
	}

	// Check that partial public keys interpolate to the public key "in the exponent"

	err = validatePartialPublicKeysInterpolateToPublicKeyInTheExponentV2(common)
	if err != nil {
		return nil, err
	}

	return keyParts, nil
}

func validateAgreementOnPublicValuesV2(partialRecoveryData []partialRecoveryDataV2) (commonDataV2, error) {

	if len(partialRecoveryData) <= 1 {
		return commonDataV2{}, fmt.Errorf("at least one partial recovery info required")
	}

	for i := 1; i < len(partialRecoveryData); i++ {

		if partialRecoveryData[0].Version != partialRecoveryData[i].Version {
			return commonDataV2{}, fmt.Errorf("versions mismatch between recovery infos 0 and %d", i)
		}
		if partialRecoveryData[0].PlayerCount != partialRecoveryData[i].PlayerCount {
			return commonDataV2{}, fmt.Errorf("player count mismatch between recovery infos 0 and %d", i)
		}
		if partialRecoveryData[0].Threshold != partialRecoveryData[i].Threshold {
			return commonDataV2{}, fmt.Errorf("threshold mismatch between recovery infos 0 and %d", i)
		}
		if partialRecoveryData[0].SharingType != partialRecoveryData[i].SharingType {
			return commonDataV2{}, fmt.Errorf("sharing type mismatch between recovery infos 0 and %d", i)
		}
		if partialRecoveryData[0].Curve != partialRecoveryData[i].Curve {
			return commonDataV2{}, fmt.Errorf("elliptic curve mismatch between recovery infos 0 and %d", i)
		}
		if !bytes.Equal(partialRecoveryData[0].AuxDataPublic, partialRecoveryData[i].AuxDataPublic) {
			return commonDataV2{}, fmt.Errorf("public aux data mismatch between recovery infos 0 and %d", i)
		}
		if !bytes.Equal(partialRecoveryData[0].AuxDataPrivateEncrypted, partialRecoveryData[i].AuxDataPrivateEncrypted) {
			return commonDataV2{}, fmt.Errorf("private aux data mismatch between recovery infos 0 and %d", i)
		}
		if !bytes.Equal(partialRecoveryData[0].AuxDataWrappedEncryptionKey, partialRecoveryData[i].AuxDataWrappedEncryptionKey) {
			return commonDataV2{}, fmt.Errorf("aux data encryption key mismatch between recovery infos 0 and %d", i)
		}
		for j, commitment := range partialRecoveryData[i].KeyShareCommitments {
			if !bytes.Equal(partialRecoveryData[0].KeyShareCommitments[j], commitment) {
				return commonDataV2{}, fmt.Errorf("key share commitment mismatch between recovery infos 0 and %d", i)
			}
		}
		if !bytes.Equal(partialRecoveryData[0].PublicKey, partialRecoveryData[i].PublicKey) {
			return commonDataV2{}, fmt.Errorf("public key mismatch between recovery infos 0 and %d", i)
		}
		if !bytes.Equal(partialRecoveryData[0].Nonce, partialRecoveryData[i].Nonce) {
			return commonDataV2{}, fmt.Errorf("nonce mismatch between recovery infos 0 and %d", i)
		}
	}

	d := commonDataV2{
		Version:                     partialRecoveryData[0].Version,
		PlayerCount:                 partialRecoveryData[0].PlayerCount,
		Threshold:                   partialRecoveryData[0].Threshold,
		SharingType:                 partialRecoveryData[0].SharingType,
		KeyShareCommitments:         partialRecoveryData[0].KeyShareCommitments,
		CurveName:                   partialRecoveryData[0].Curve,
		PublicKeyBytes:              partialRecoveryData[0].PublicKey,
		AuxDataPublic:               partialRecoveryData[0].AuxDataPublic,
		AuxDataPrivateEncrypted:     partialRecoveryData[0].AuxDataPrivateEncrypted,
		AuxDataWrappedEncryptionKey: partialRecoveryData[0].AuxDataWrappedEncryptionKey,
		Nonce:                       partialRecoveryData[0].Nonce,
	}

	var err error
	d.Curve, err = math.NewCurve(d.CurveName)
	if err != nil {
		return commonDataV2{}, fmt.Errorf("invalid curve: %s", d.CurveName)
	}

	d.PublicKey, err = d.Curve.DecodePoint(d.PublicKeyBytes)
	if err != nil {
		return commonDataV2{}, fmt.Errorf("invalid public key: %w", err)
	}

	return d, nil
}

func validateZeroKnowledgeProofV2(d commonDataV2, ersPublicKey *rsa.PublicKey, ersLabel []byte, recoveryInfo partialRecoveryDataV2) (recoveryDataKeyPart, error) {

	var err error
	i := recoveryInfo.PlayerIndex

	if len(recoveryInfo.KeyShareCommitments) != d.PlayerCount {
		return recoveryDataKeyPart{}, fmt.Errorf("invalid number of key share commitments for recovery info %d", i)
	}
	if len(recoveryInfo.Combination) != k {
		return recoveryDataKeyPart{}, fmt.Errorf("invalid number of elements in combination for recovery info %d", i)
	}
	if len(recoveryInfo.Es) != n {
		return recoveryDataKeyPart{}, fmt.Errorf("invalid number of encrypted values for recovery info %d", i)
	}
	if len(recoveryInfo.Rs) != k {
		return recoveryDataKeyPart{}, fmt.Errorf("invalid number of random values for recovery info %d", i)
	}
	if len(recoveryInfo.Vs) != k {
		return recoveryDataKeyPart{}, fmt.Errorf("invalid number of plaintext values for recovery info %d", i)
	}
	if len(recoveryInfo.Ys) != k {
		return recoveryDataKeyPart{}, fmt.Errorf("invalid number of commitments for recovery info %d", i)
	}

	keyPart := recoveryDataKeyPart{
		PartCommitment:  recoveryInfo.KeyShareCommitments[i],
		Values:          make(map[int][]byte),
		EncryptedValues: make(map[int][]byte),
	}

	// Decode commitments

	commitments := make([]math.Point, k+1)
	commitments[0], err = d.Curve.DecodePoint(recoveryInfo.KeyShareCommitments[i])
	if err != nil {
		return recoveryDataKeyPart{}, fmt.Errorf("error decoding key share commitment for recovery info %d", i)
	}
	for j := 0; j < k; j++ {
		commitments[j+1], err = d.Curve.DecodePoint(recoveryInfo.Ys[j])
		if err != nil {
			return recoveryDataKeyPart{}, fmt.Errorf("error decoding key share commitment for recovery info %d at index %d", i, j)
		}
	}

	// Check combination

	ctxData := ContextData{
		RecoveryDataVersion:         d.Version,
		PlayerCount:                 d.PlayerCount,
		Threshold:                   d.Threshold,
		SharingType:                 d.SharingType,
		CurveName:                   d.CurveName,
		PlayerIndex:                 recoveryInfo.PlayerIndex,
		Nonce:                       d.Nonce,
		AuxDataPublic:               d.AuxDataPublic,
		AuxDataPrivateEncrypted:     d.AuxDataPrivateEncrypted,
		AuxDataWrappedEncryptionKey: d.AuxDataWrappedEncryptionKey,
	}
	expectedCombinations := hashToCombination(d.Version, n, k, d.PublicKey.Encode(), recoveryInfo.Es, recoveryInfo.Ys, recoveryInfo.KeyShareCommitments[i], ctxData)
	if !reflect.DeepEqual(expectedCombinations, recoveryInfo.Combination) {
		return recoveryDataKeyPart{}, fmt.Errorf("combination does not match expected value for recovery info %d", i)
	}

	for j, c := range recoveryInfo.Combination {

		keyPart.Values[c+1] = recoveryInfo.Vs[j]
		vj := d.Curve.NewScalarBytes(recoveryInfo.Vs[j])

		// Check that the correct randomness (Rs) is used for encryption (Es) of the opened values (Vs)

		if ersPublicKey != nil {
			ciphertext, err := rsa.EncryptOAEP(sha256.New(), bytes.NewReader(recoveryInfo.Rs[j]), ersPublicKey, recoveryInfo.Vs[j], ersLabel)
			if err != nil {
				return recoveryDataKeyPart{}, fmt.Errorf("encryption failed for recovery info %d at index %d: %s", i, j, err)
			}
			if !bytes.Equal(ciphertext, recoveryInfo.Es[c]) {
				return recoveryDataKeyPart{}, fmt.Errorf("encryption opening failed for recovery info %d at index %d: %s", i, j, err)
			}
		}

		// Check that the plaintext values match the commitments (Ys)

		var expectedCommitment math.Point
		if c < k {
			expectedCommitment = commitments[c+1]
		} else {
			expectedCommitment, err = math.RecombineInExponent(c+2, k, commitments)
			if err != nil {
				return recoveryDataKeyPart{}, fmt.Errorf("error computing commitment for recovery info %d", i)
			}
		}

		if !d.Curve.G().Mul(vj).Equals(expectedCommitment) {
			return recoveryDataKeyPart{}, fmt.Errorf("commitment equality check failed for recovery info %d at index %d", i, j)
		}
	}

	combinationIndex := 0
	for j, e := range recoveryInfo.Es {
		if combinationIndex < len(recoveryInfo.Combination) && recoveryInfo.Combination[combinationIndex] == j {
			combinationIndex += 1
			continue
		}
		keyPart.EncryptedValues[j+1] = e
	}

	return keyPart, nil

}

func validatePartialPublicKeysInterpolateToPublicKeyInTheExponentV2(d commonDataV2) error {

	var err error
	commitments := make([]math.Point, d.PlayerCount)
	for i := 0; i < len(d.KeyShareCommitments); i++ {
		commitments[i], err = d.Curve.DecodePoint(d.KeyShareCommitments[i])
		if err != nil {
			return fmt.Errorf("error decoding key share commitment at index %d", i)
		}
	}

	var recombinedPublicKey math.Point
	switch d.SharingType {
	case shamir:

		// Recombine public key from the first points 1, 2, ..., t+1

		recombinedPublicKey, err = math.RecombineInExponent(0, d.Threshold, commitments)
		if err != nil {
			return fmt.Errorf("error recombining public key: %w", err)
		}

		// Check that the commitments for t+2, t+3, ..., n are consistent with the same polynomial

		xs := make([]int, d.Threshold+1)
		ys := make([]math.Point, d.Threshold+1)
		for i := 0; i < d.Threshold; i++ {
			xs[i] = i + 1
			ys[i] = commitments[i]
		}
		for i := d.Threshold + 1; i < d.PlayerCount; i++ {
			xs[d.Threshold] = i + 1
			ys[d.Threshold] = commitments[i]

			otherRecombinedPublicKey, err := math.RecombineInExponent2(0, d.Threshold, xs, ys)
			if err != nil {
				return fmt.Errorf("error recombining public key: %w", err)
			}

			if !recombinedPublicKey.Equals(otherRecombinedPublicKey) {
				return fmt.Errorf("commitments are not consistent with a degree %d polynomial", d.Threshold)
			}
		}
		if !recombinedPublicKey.Equals(d.PublicKey) {
			return fmt.Errorf("key share commitments do not recombine to public key")
		}

	case additive:
		recombinedPublicKey = commitments[0]
		for i := 1; i < d.PlayerCount; i++ {
			recombinedPublicKey = recombinedPublicKey.Add(commitments[i])
		}
		if !recombinedPublicKey.Equals(d.PublicKey) {
			return fmt.Errorf("key share commitments do not recombine to public key")
		}

	case multiplicative:

		// We currently don't validate correctness of key shares commitments for multiplicative sharings;
		// this requires additional zero knowledge proofs. In the case of a multiplicative sharing, we currently
		// only call validate() in Combine(), where we know that at least one player is honest, and so the
		// individual key shares are validated by just checking that all players agree on them.

	default:
		return fmt.Errorf("unsupported sharing type: %s", d.SharingType)
	}

	return nil
}
