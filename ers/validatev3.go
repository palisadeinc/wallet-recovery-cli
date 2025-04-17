package ers

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/palisadeinc/mpc-recovery/math"
	"golang.org/x/sync/errgroup"
	"reflect"
	"sort"
	"sync"
)

// This is data contained in each player's partial recovery data and on which the players should agree.
type commonDataV3 struct {
	Version                     string
	Threshold                   int
	SharingType                 string
	CurveName                   string
	AuxDataPublic               []byte
	AuxDataPrivateEncrypted     []byte
	AuxDataWrappedEncryptionKey []byte
	KeyShareCommitments         map[int][]byte
	PublicKeyBytes              []byte
	Nonce                       []byte

	Curve     math.Curve
	PublicKey math.Point
}

func validateJSONV3(ersPublicKey rsa.PublicKey, label []byte, publicKeyBytes, recoveryDataJSON []byte) error {

	var recoveryData recoveryDataV3
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

	_, err = validateV3(recoveryData, &ersPublicKey, label, publicKeyBytes)
	if err != nil {
		return err
	}

	return nil
}

func validateV3(recoveryData recoveryDataV3, ersPublicKey *rsa.PublicKey, ersLabel []byte, externalPublicKey []byte) (map[int]recoveryDataKeyPart, error) {
	// Check that all partial recovery data agree on public values

	common, err := validateAgreementOnPublicValues(recoveryData.PartialRecoveryData)
	if err != nil {
		return nil, err
	}

	if common.Version != recoveryData.Version {
		return nil, fmt.Errorf("unsupported partial recovery data version: %s", common.Version)
	}

	// Check that the threshold allows us to recover based on the number of partial recovery data

	if len(recoveryData.PartialRecoveryData) <= common.Threshold {
		return nil, fmt.Errorf("not enough partial recovery data (%d) for threshold: %d", len(recoveryData.PartialRecoveryData), common.Threshold)
	}

	// Check that the elliptic curve is supported

	_, err = math.NewCurve(common.CurveName)
	if err != nil {
		return nil, err
	}

	// Check that the sharing type is supported

	switch common.SharingType {
	case additive, shamir:
		// OK
	case multiplicative:
		// We only support validation of multiplicative sharings in the case where we know that
		// at least one of the nodes is honest; to validate multiplicative sharings against an external
		// public key alone would require additional zero knowledge proofs.
		if externalPublicKey != nil {
			return nil, fmt.Errorf("validating multiplicative sharing with external public key not supported")
		}
	default:
		return nil, fmt.Errorf("unsupported sharing type: %s", common.SharingType)
	}

	// If an external public key is provided, validate that it matches the public key contained in the partial recovery data

	if externalPublicKey != nil && !bytes.Equal(common.PublicKey.Encode(), externalPublicKey) {
		fmt.Println("external", base64.StdEncoding.EncodeToString(externalPublicKey))
		fmt.Println("internal", base64.StdEncoding.EncodeToString(common.PublicKey.Encode()))
		return nil, fmt.Errorf("mismatch between provided public key and public key contained in the partial recovery data")
	}

	// Validate the individual zero-knowledge proofs from each player

	keyParts := make(map[int]recoveryDataKeyPart)
	keyPartsLock := sync.Mutex{}

	var eg errgroup.Group

	for _, partialRecoveryData := range recoveryData.PartialRecoveryData {
		partialRecoveryData := partialRecoveryData
		eg.Go(func() error {
			keyPart, err := validateZeroKnowledgeProof(partialRecoveryData, common, ersPublicKey, ersLabel)
			if err != nil {
				return err
			}

			keyPartsLock.Lock()
			keyParts[partialRecoveryData.PlayerIndex] = keyPart
			keyPartsLock.Unlock()

			return nil
		})
	}

	err = eg.Wait()
	if err != nil {
		return nil, err
	}

	// Check that partial public keys corresponds to the public

	err = validatePartialPublicKeysInterpolateToPublicKeyInTheExponentV3(common)
	if err != nil {
		return nil, err
	}

	return keyParts, nil
}

func validateAgreementOnPublicValues(partialRecoveryData []partialRecoveryDataV3) (commonDataV3, error) {
	if len(partialRecoveryData) < 2 {
		return commonDataV3{}, fmt.Errorf("at least two partial recovery data required")
	}

	for i := 1; i < len(partialRecoveryData); i++ {
		if partialRecoveryData[0].Version != partialRecoveryData[i].Version {
			return commonDataV3{}, fmt.Errorf("versions mismatch between recovery data 0 and %d", i)
		}
		if partialRecoveryData[0].Threshold != partialRecoveryData[i].Threshold {
			return commonDataV3{}, fmt.Errorf("threshold mismatch between recovery data 0 and %d", i)
		}
		if partialRecoveryData[0].SharingType != partialRecoveryData[i].SharingType {
			return commonDataV3{}, fmt.Errorf("sharing type mismatch between recovery data 0 and %d", i)
		}
		if partialRecoveryData[0].Curve != partialRecoveryData[i].Curve {
			return commonDataV3{}, fmt.Errorf("elliptic curve mismatch between recovery data 0 and %d", i)
		}
		if !bytes.Equal(partialRecoveryData[0].AuxDataPublic, partialRecoveryData[i].AuxDataPublic) {
			return commonDataV3{}, fmt.Errorf("public aux data mismatch between recovery data 0 and %d", i)
		}
		if !bytes.Equal(partialRecoveryData[0].AuxDataPrivateEncrypted, partialRecoveryData[i].AuxDataPrivateEncrypted) {
			return commonDataV3{}, fmt.Errorf("private aux data mismatch between recovery data 0 and %d", i)
		}
		if !bytes.Equal(partialRecoveryData[0].AuxDataWrappedEncryptionKey, partialRecoveryData[i].AuxDataWrappedEncryptionKey) {
			return commonDataV3{}, fmt.Errorf("aux data encryption key mismatch between recovery data 0 and %d", i)
		}
		if !reflect.DeepEqual(partialRecoveryData[0].KeyShareCommitments, partialRecoveryData[i].KeyShareCommitments) {
			return commonDataV3{}, fmt.Errorf("key share commitments mismatch between recovery data 0 and %d", i)
		}
		if !bytes.Equal(partialRecoveryData[0].PublicKey, partialRecoveryData[i].PublicKey) {
			return commonDataV3{}, fmt.Errorf("public key mismatch between recovery data 0 and %d", i)
		}
		if !bytes.Equal(partialRecoveryData[0].Nonce, partialRecoveryData[i].Nonce) {
			return commonDataV3{}, fmt.Errorf("nonce mismatch between recovery data 0 and %d", i)
		}
	}

	d := commonDataV3{
		Version:                     partialRecoveryData[0].Version,
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
		return commonDataV3{}, fmt.Errorf("invalid curve: %s", d.CurveName)
	}

	d.PublicKey, err = d.Curve.DecodePoint(d.PublicKeyBytes)
	if err != nil {
		return commonDataV3{}, fmt.Errorf("invalid public key: %w", err)
	}

	return d, nil
}

func validateZeroKnowledgeProof(partialRecoveryData partialRecoveryDataV3, common commonDataV3, ersPublicKey *rsa.PublicKey, ersLabel []byte) (recoveryDataKeyPart, error) {
	if _, exists := common.KeyShareCommitments[partialRecoveryData.PlayerIndex]; !exists {
		return recoveryDataKeyPart{}, fmt.Errorf("no key share commitment for partial recovery data %d", partialRecoveryData.PlayerIndex)
	}
	if len(partialRecoveryData.Combination) != k {
		return recoveryDataKeyPart{}, fmt.Errorf("invalid number of elements in combination for partial recovery data %d", partialRecoveryData.PlayerIndex)
	}
	if len(partialRecoveryData.Es) != n {
		return recoveryDataKeyPart{}, fmt.Errorf("invalid number of encrypted values for partial recovery data %d", partialRecoveryData.PlayerIndex)
	}
	if len(partialRecoveryData.Rs) != k {
		return recoveryDataKeyPart{}, fmt.Errorf("invalid number of random values for partial recovery data %d", partialRecoveryData.PlayerIndex)
	}
	if len(partialRecoveryData.Vs) != k {
		return recoveryDataKeyPart{}, fmt.Errorf("invalid number of plaintext values for partial recovery data %d", partialRecoveryData.PlayerIndex)
	}
	if len(partialRecoveryData.Ys) != k {
		return recoveryDataKeyPart{}, fmt.Errorf("invalid number of commitments for parial recovery data %d", partialRecoveryData.PlayerIndex)
	}

	keyPart := recoveryDataKeyPart{
		PartCommitment:  partialRecoveryData.KeyShareCommitments[partialRecoveryData.PlayerIndex],
		Values:          make(map[int][]byte),
		EncryptedValues: make(map[int][]byte),
	}

	// Decode commitments

	var err error
	commitments := make([]math.Point, n+1)
	commitments[0], err = common.Curve.DecodePoint(partialRecoveryData.KeyShareCommitments[partialRecoveryData.PlayerIndex])
	if err != nil {
		return recoveryDataKeyPart{}, fmt.Errorf("error decoding key share commitment for recovery data %d", partialRecoveryData.PlayerIndex)
	}
	for j := 0; j < k; j++ {
		commitments[j+1], err = common.Curve.DecodePoint(partialRecoveryData.Ys[j])
		if err != nil {
			return recoveryDataKeyPart{}, fmt.Errorf("error decoding key share commitment for recovery data %d at index %d", partialRecoveryData.PlayerIndex, j)
		}
	}

	xs := make([]int, k+1)
	for i := range xs {
		xs[i] = i
	}
	for j := k; j < n; j++ {
		commitments[j+1], err = math.RecombineInExponent2(j+1, k, xs, commitments[0:k+1])
	}

	// Check combination

	ctxData := ContextData{
		RecoveryDataVersion:         common.Version,
		Threshold:                   common.Threshold,
		SharingType:                 common.SharingType,
		CurveName:                   common.CurveName,
		PlayerIndex:                 partialRecoveryData.PlayerIndex,
		Nonce:                       common.Nonce,
		AuxDataPublic:               common.AuxDataPublic,
		AuxDataPrivateEncrypted:     common.AuxDataPrivateEncrypted,
		AuxDataWrappedEncryptionKey: common.AuxDataWrappedEncryptionKey,
	}
	expectedCombinations := hashToCombination(common.Version, n, k, common.PublicKey.Encode(), partialRecoveryData.Es, partialRecoveryData.Ys, partialRecoveryData.KeyShareCommitments[partialRecoveryData.PlayerIndex], ctxData)
	if !reflect.DeepEqual(expectedCombinations, partialRecoveryData.Combination) {
		return recoveryDataKeyPart{}, fmt.Errorf("combination does not match expected value for recovery data %d", partialRecoveryData.PlayerIndex)
	}

	for j, c := range partialRecoveryData.Combination {
		// Check that plaintext can be decoded

		keyPart.Values[c+1] = partialRecoveryData.Vs[j]
		vj := common.Curve.NewScalarBytes(partialRecoveryData.Vs[j])

		// Check that the correct randomness (Rs) is used for encryption (Es) of the opened values (Vs)

		if ersPublicKey != nil {
			ciphertext, err := rsa.EncryptOAEP(sha256.New(), bytes.NewReader(partialRecoveryData.Rs[j]), ersPublicKey, partialRecoveryData.Vs[j], ersLabel)
			if err != nil {
				return recoveryDataKeyPart{}, fmt.Errorf("encryption failed for recovery data %d at index %d: %s", partialRecoveryData.PlayerIndex, j, err)
			}
			if !bytes.Equal(ciphertext, partialRecoveryData.Es[c]) {
				return recoveryDataKeyPart{}, fmt.Errorf("encryption opening failed for recovery data %d at index %d: %s", partialRecoveryData.PlayerIndex, j, err)
			}
		}

		// Check that the plaintext values match the commitments (Ys)

		if !common.Curve.G().Mul(vj).Equals(commitments[c+1]) {
			return recoveryDataKeyPart{}, fmt.Errorf("commitment equality check failed for recovery data %d at index %d", partialRecoveryData.PlayerIndex, j)
		}
	}

	combinationIndex := 0
	for j, e := range partialRecoveryData.Es {
		if combinationIndex < len(partialRecoveryData.Combination) && partialRecoveryData.Combination[combinationIndex] == j {
			combinationIndex += 1
			continue
		}
		keyPart.EncryptedValues[j+1] = e
	}

	return keyPart, nil
}

func validatePartialPublicKeysInterpolateToPublicKeyInTheExponentV3(d commonDataV3) error {
	keyShareCommitments := make(map[int]math.Point, len(d.KeyShareCommitments))
	for i := 0; i < len(d.KeyShareCommitments); i++ {
		var err error
		keyShareCommitments[i], err = d.Curve.DecodePoint(d.KeyShareCommitments[i])
		if err != nil {
			return fmt.Errorf("error decoding key share commitment at index %d", i)
		}
	}

	var recombinedPublicKey math.Point
	switch d.SharingType {
	case shamir:
		sortedCommitmentIndices := make([]int, 0, len(keyShareCommitments))
		for i := range keyShareCommitments {
			sortedCommitmentIndices = append(sortedCommitmentIndices, i+1)
		}
		sort.Ints(sortedCommitmentIndices)

		sortedCommitments := make([]math.Point, 0, len(keyShareCommitments))
		for _, i := range sortedCommitmentIndices {
			sortedCommitments = append(sortedCommitments, keyShareCommitments[i-1])
		}

		// Recombine public key from all points to check that they are consistent
		for i := 0; i < len(keyShareCommitments)-d.Threshold; i++ {
			var err error
			recombinedPublicKey, err = math.RecombineInExponent2(0, d.Threshold, sortedCommitmentIndices[i:], sortedCommitments[i:])
			if err != nil {
				return err
			}
			if !recombinedPublicKey.Equals(d.PublicKey) {
				return fmt.Errorf("key share commitments are not consistent")
			}
		}
	case additive:
		recombinedPublicKey = d.Curve.O()
		for _, keyShareCommitment := range keyShareCommitments {
			recombinedPublicKey = recombinedPublicKey.Add(keyShareCommitment)
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
