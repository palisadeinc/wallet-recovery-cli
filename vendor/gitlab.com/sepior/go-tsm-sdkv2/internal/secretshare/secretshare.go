package secretshare

import (
	"gitlab.com/sepior/go-tsm-sdkv2/ec"
	"gitlab.com/sepior/go-tsm-sdkv2/internal/polynomial"
)

type SharingType int

const (
	ShamirSharing   SharingType = 1
	AdditiveSharing SharingType = 2
)

func (s SharingType) String() string {
	i := s - 1
	if i < 0 || int(i) >= len(sharingTypes) {
		return "unknown"
	}
	return sharingTypes[i]
}

var sharingTypes = []string{"shamir", "additive"}

func ShamirSecretShare(players []int, threshold int, secret ec.Scalar) map[int]ec.Scalar {
	poly := polynomial.NewRandomPolynomial(threshold, secret)

	secretShares := make(map[int]ec.Scalar, len(players))
	for _, i := range players {
		secretShares[i] = poly.Eval(secret.Field().NewScalarIntWithModularReduction(i + 1))
	}
	return secretShares
}

func AdditiveSecretShare(playerCount int, secret ec.Scalar) map[int]ec.Scalar {
	secretShares := make(map[int]ec.Scalar, playerCount)

	value := secret.Field().Zero()
	for i := 1; i < playerCount; i++ {
		v := value.Field().NewRandomScalar()
		secretShares[i] = v
		value = value.Add(v)
	}
	secretShares[0] = secret.Subtract(value)
	return secretShares
}
