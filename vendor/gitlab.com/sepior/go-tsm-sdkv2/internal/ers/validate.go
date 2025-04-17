package ers

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"gitlab.com/sepior/go-tsm-sdkv2/ec"
	"gitlab.com/sepior/go-tsm-sdkv2/internal/polynomial"
	"gitlab.com/sepior/go-tsm-sdkv2/internal/secretshare"
	"golang.org/x/sync/errgroup"
	"reflect"
	"sync"
)

// Validate validates recovery data using the ERS public key and an external public key. If no error is returned, the
// private key corresponding to the provided external public key is guaranteed to be recoverable from the recovery data
// using the private ERS key.
func Validate(recoveryData RecoveryData, ersPublicKey *rsa.PublicKey, ersLabel []byte, externalPublicKey ec.Point) error {
	_, _, _, err := validate(recoveryData, ersPublicKey, ersLabel, &externalPublicKey)
	return err
}

type recoveryDataKeyPart struct {
	PartCommitment  []byte
	Values          map[int][]byte
	EncryptedValues map[int][]byte
}

func validate(recoveryData RecoveryData, ersPublicKey *rsa.PublicKey, ersLabel []byte, externalPublicKey *ec.Point) (int, string, map[int]recoveryDataKeyPart, error) {
	if recoveryData.Version != Version {
		return 0, "", nil, fmt.Errorf("validation not supported for recovery data version: %s", recoveryData.Version)
	}

	// Check that all partial recovery data agree on public values

	common, err := validateAgreementOnPublicValues(recoveryData.PartialRecoveryData)
	if err != nil {
		return 0, "", nil, err
	}

	if common.Version != Version {
		return 0, "", nil, fmt.Errorf("unsupported partial recovery data version: %s", common.Version)
	}

	// Check that the threshold allows us to recover based on the number of partial recovery data

	if len(recoveryData.PartialRecoveryData) <= common.Threshold {
		return 0, "", nil, fmt.Errorf("not enough partial recovery data (%d) for threshold: %d", len(recoveryData.PartialRecoveryData), common.Threshold)
	}

	// Check that the elliptic curve is supported

	_, err = ec.NewCurve(common.CurveName)
	if err != nil {
		return 0, "", nil, err
	}

	// Check that the sharing type is supported

	switch common.SharingType {
	case secretshare.ShamirSharing.String(), secretshare.AdditiveSharing.String():
		// OK
	default:
		return 0, "", nil, fmt.Errorf("unsupported sharing type: %s", common.SharingType)
	}

	// If an external public key is provided, validate that it matches the public key contained in the partial recovery data

	if externalPublicKey != nil && !common.PublicKey.Equals(*externalPublicKey) {
		return 0, "", nil, fmt.Errorf("mismatch between provided public key and public key contained in the partial recovery data")
	}

	// Validate the individual zero-knowledge proofs from each player

	keyParts := make(map[int]recoveryDataKeyPart, len(recoveryData.PartialRecoveryData))
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
		return 0, "", nil, err
	}

	// Check that partial public keys corresponds to the public

	err = validatePartialPublicKeysInterpolateToPublicKeyInTheExponent(common)
	if err != nil {
		return 0, "", nil, err
	}

	return common.Threshold, common.SharingType, keyParts, nil
}

// This is data contained in each player's partial recovery data and on which the players should agree.
type commonData struct {
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

	Curve     ec.Curve
	PublicKey ec.Point
}

func validateAgreementOnPublicValues(partialRecoveryData []PartialRecoveryData) (commonData, error) {
	if len(partialRecoveryData) < 2 {
		return commonData{}, fmt.Errorf("at least two partial recovery data required")
	}

	for i := 1; i < len(partialRecoveryData); i++ {
		if partialRecoveryData[0].Version != partialRecoveryData[i].Version {
			return commonData{}, fmt.Errorf("versions mismatch between recovery data 0 and %d", i)
		}
		if partialRecoveryData[0].Threshold != partialRecoveryData[i].Threshold {
			return commonData{}, fmt.Errorf("threshold mismatch between recovery data 0 and %d", i)
		}
		if partialRecoveryData[0].SharingType != partialRecoveryData[i].SharingType {
			return commonData{}, fmt.Errorf("sharing type mismatch between recovery data 0 and %d", i)
		}
		if partialRecoveryData[0].Curve != partialRecoveryData[i].Curve {
			return commonData{}, fmt.Errorf("elliptic curve mismatch between recovery data 0 and %d", i)
		}
		if !bytes.Equal(partialRecoveryData[0].AuxDataPublic, partialRecoveryData[i].AuxDataPublic) {
			return commonData{}, fmt.Errorf("public aux data mismatch between recovery data 0 and %d", i)
		}
		if !bytes.Equal(partialRecoveryData[0].AuxDataPrivateEncrypted, partialRecoveryData[i].AuxDataPrivateEncrypted) {
			return commonData{}, fmt.Errorf("private aux data mismatch between recovery data 0 and %d", i)
		}
		if !bytes.Equal(partialRecoveryData[0].AuxDataWrappedEncryptionKey, partialRecoveryData[i].AuxDataWrappedEncryptionKey) {
			return commonData{}, fmt.Errorf("aux data encryption key mismatch between recovery data 0 and %d", i)
		}
		if !reflect.DeepEqual(partialRecoveryData[0].KeyShareCommitments, partialRecoveryData[i].KeyShareCommitments) {
			return commonData{}, fmt.Errorf("key share commitments mismatch between recovery data 0 and %d", i)
		}
		if !bytes.Equal(partialRecoveryData[0].PublicKey, partialRecoveryData[i].PublicKey) {
			return commonData{}, fmt.Errorf("public key mismatch between recovery data 0 and %d", i)
		}
		if !bytes.Equal(partialRecoveryData[0].Nonce, partialRecoveryData[i].Nonce) {
			return commonData{}, fmt.Errorf("nonce mismatch between recovery data 0 and %d", i)
		}
	}

	d := commonData{
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
	d.Curve, err = ec.NewCurve(d.CurveName)
	if err != nil {
		return commonData{}, fmt.Errorf("invalid curve: %s", d.CurveName)
	}

	d.PublicKey, err = d.Curve.DecodePoint(d.PublicKeyBytes, true)
	if err != nil {
		return commonData{}, fmt.Errorf("invalid public key: %w", err)
	}

	return d, nil
}

func validateZeroKnowledgeProof(partialRecoveryData PartialRecoveryData, common commonData, ersPublicKey *rsa.PublicKey, ersLabel []byte) (recoveryDataKeyPart, error) {
	if _, exists := common.KeyShareCommitments[partialRecoveryData.PlayerIndex]; !exists {
		return recoveryDataKeyPart{}, fmt.Errorf("no key share commitment for partial recovery data %d", partialRecoveryData.PlayerIndex)
	}
	if len(partialRecoveryData.Combination) != K {
		return recoveryDataKeyPart{}, fmt.Errorf("invalid number of elements in combination for partial recovery data %d", partialRecoveryData.PlayerIndex)
	}
	if len(partialRecoveryData.Es) != N {
		return recoveryDataKeyPart{}, fmt.Errorf("invalid number of encrypted values for partial recovery data %d", partialRecoveryData.PlayerIndex)
	}
	if len(partialRecoveryData.Rs) != K {
		return recoveryDataKeyPart{}, fmt.Errorf("invalid number of random values for partial recovery data %d", partialRecoveryData.PlayerIndex)
	}
	if len(partialRecoveryData.Vs) != K {
		return recoveryDataKeyPart{}, fmt.Errorf("invalid number of plaintext values for partial recovery data %d", partialRecoveryData.PlayerIndex)
	}
	if len(partialRecoveryData.Ys) != K {
		return recoveryDataKeyPart{}, fmt.Errorf("invalid number of commitments for parial recovery data %d", partialRecoveryData.PlayerIndex)
	}

	keyPart := recoveryDataKeyPart{
		PartCommitment:  partialRecoveryData.KeyShareCommitments[partialRecoveryData.PlayerIndex],
		Values:          make(map[int][]byte),
		EncryptedValues: make(map[int][]byte),
	}

	// Decode commitments

	var err error
	commitments := make([]ec.Point, N+1)
	commitments[0], err = common.Curve.DecodePoint(partialRecoveryData.KeyShareCommitments[partialRecoveryData.PlayerIndex], true)
	if err != nil {
		return recoveryDataKeyPart{}, fmt.Errorf("error decoding key share commitment for recovery data %d", partialRecoveryData.PlayerIndex)
	}
	for j := 0; j < K; j++ {
		commitments[j+1], err = common.Curve.DecodePoint(partialRecoveryData.Ys[j], true)
		if err != nil {
			return recoveryDataKeyPart{}, fmt.Errorf("error decoding key share commitment for recovery data %d at index %d", partialRecoveryData.PlayerIndex, j)
		}
	}
	diffEngine := polynomial.NewDifferenceEngineInExponent(commitments[0 : K+1])
	for j := K; j < N; j++ {
		commitments[j+1] = diffEngine.Next(1)
	}

	// Check combination

	ctxData := RecoveryContext{
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
	expectedCombinations := HashToCombination(common.PublicKey.Encode(), partialRecoveryData.Es, partialRecoveryData.Ys, partialRecoveryData.KeyShareCommitments[partialRecoveryData.PlayerIndex], ctxData)
	if !reflect.DeepEqual(expectedCombinations, partialRecoveryData.Combination) {
		return recoveryDataKeyPart{}, fmt.Errorf("combination does not match expected value for recovery data %d", partialRecoveryData.PlayerIndex)
	}

	for j, c := range partialRecoveryData.Combination {
		// Check that plaintext can be decoded

		keyPart.Values[c+1] = partialRecoveryData.Vs[j]
		vj, err := common.Curve.Zn().DecodeScalar(partialRecoveryData.Vs[j])
		if err != nil {
			return recoveryDataKeyPart{}, fmt.Errorf("error decoding key share for recovery data %d at index %d", partialRecoveryData.PlayerIndex, j)
		}

		// Check that the correct randomness (Rs) is used for encryption (Es) of the opened values (Vs)

		ciphertext, err := rsa.EncryptOAEP(sha256.New(), bytes.NewReader(partialRecoveryData.Rs[j]), ersPublicKey, partialRecoveryData.Vs[j], ersLabel)
		if err != nil {
			return recoveryDataKeyPart{}, fmt.Errorf("encryption failed for recovery data %d at index %d: %s", partialRecoveryData.PlayerIndex, j, err)
		}
		if !bytes.Equal(ciphertext, partialRecoveryData.Es[c]) {
			return recoveryDataKeyPart{}, fmt.Errorf("encryption opening failed for recovery data %d at index %d: %s", partialRecoveryData.PlayerIndex, j, err)
		}

		// Check that the plaintext values match the commitments (Ys)

		if !common.Curve.G().MultiplyVarTime(vj).Equals(commitments[c+1]) {
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

func validatePartialPublicKeysInterpolateToPublicKeyInTheExponent(d commonData) error {
	keyShareCommitments := make(map[int]ec.Point, len(d.KeyShareCommitments))
	for i := 0; i < len(d.KeyShareCommitments); i++ {
		var err error
		keyShareCommitments[i], err = d.Curve.DecodePoint(d.KeyShareCommitments[i], true)
		if err != nil {
			return fmt.Errorf("error decoding key share commitment at index %d", i)
		}
	}

	var recombinedPublicKey ec.Point
	switch d.SharingType {
	case secretshare.ShamirSharing.String():
		// Recombine public key from the first points 1, 2, ..., t+1
		recombinedPublicKey = polynomial.InterpolatePlayersInExponent(d.Curve.Zn().Zero(), d.Threshold, keyShareCommitments)
		if !recombinedPublicKey.Equals(d.PublicKey) {
			return fmt.Errorf("key share commitments do not recombine to public key")
		}

		// Check that the commitments for t+2, t+3, ..., n are consistent with the same polynomial
		err := polynomial.AssertPlayersExponentsOnSamePolynomial(d.Threshold, keyShareCommitments)
		if err != nil {
			return err
		}
	case secretshare.AdditiveSharing.String():
		recombinedPublicKey = d.Curve.O()
		for _, keyShareCommitment := range keyShareCommitments {
			recombinedPublicKey = recombinedPublicKey.Add(keyShareCommitment)
		}
		if !recombinedPublicKey.Equals(d.PublicKey) {
			return fmt.Errorf("key share commitments do not recombine to public key")
		}
	default:
		return fmt.Errorf("unsupported sharing type: %s", d.SharingType)
	}

	return nil
}
