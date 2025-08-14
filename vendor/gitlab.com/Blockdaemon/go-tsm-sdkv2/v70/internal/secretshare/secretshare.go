package secretshare

import (
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/ec"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/polynomial"
)

type SharingType int

const (
	ShamirSharing        SharingType = 1 // Shamir sharing over a finite field
	AdditiveSharing      SharingType = 2 // Additive sharing over a finite field
	XORSharingAES        SharingType = 3 // Additive xor sharing with AES checksum
	XORSharingHMAC       SharingType = 4 // Additive xor sharing with HMAC checksum
	ADN06Sharing         SharingType = 5 // Replicated integer sharing
	XORReplicatedSharing SharingType = 6 // Replicated xor sharing
	XORBedozaSharing     SharingType = 7 // Additive xor sharing where each player holds an information theoretic mac on all other player shares
)

func (s SharingType) String() string {
	i := s - 1
	if i < 0 || int(i) >= len(sharingTypes) {
		return "unknown"
	}
	return sharingTypes[i]
}

var sharingTypes = []string{"shamir", "additive", "xor-aes", "xor-hmac", "adn06", "xor-replicated", "xor-bedoza"}

func ShamirSecretShare(players []int, threshold int, secret ec.Scalar) (map[int]ec.Scalar, error) {
	if threshold <= 0 {
		return nil, fmt.Errorf("invalid threshold: %d", threshold)
	}
	if len(players) <= threshold {
		return nil, fmt.Errorf("threshold must be less than the number of players")
	}

	poly := polynomial.NewRandomPolynomial(threshold, secret)

	secretShares := make(map[int]ec.Scalar, len(players))
	for _, i := range players {
		xCoordinate := i + 1
		if xCoordinate == 0 {
			return nil, fmt.Errorf("invalid player index: %d", i)
		}
		secretShares[i] = poly.Eval(secret.Field().NewScalarIntWithModularReduction(xCoordinate))
	}
	return secretShares, nil
}

func ShamirRecoverSecret(threshold int, shares map[int]ec.Scalar) (ec.Scalar, error) {
	if threshold <= 0 {
		return ec.Scalar{}, fmt.Errorf("invalid threshold: %d", threshold)
	}
	if len(shares) <= threshold {
		return ec.Scalar{}, fmt.Errorf("threshold must be less than the number of players")
	}

	var zn ec.Field
	for _, s := range shares {
		if zn == nil {
			zn = s.Field()
		}
		if !zn.Equals(s.Field()) {
			return ec.Scalar{}, fmt.Errorf("not all shares are from the same finite field")
		}
	}
	if zn == nil {
		return ec.Scalar{}, fmt.Errorf("zn is nil")
	}

	secret := polynomial.InterpolatePlayers(zn.Zero(), threshold, shares)
	return secret, nil
}

func AdditiveSecretShare(playerCount int, secret ec.Scalar) (map[int]ec.Scalar, error) {
	if playerCount < 2 {
		return nil, fmt.Errorf("invalid player count: %d", playerCount)
	}

	secretShares := make(map[int]ec.Scalar, playerCount)

	value := secret.Field().Zero()
	for i := 1; i < playerCount; i++ {
		v := value.Field().NewRandomScalar()
		secretShares[i] = v
		value = value.Add(v)
	}
	secretShares[0] = secret.Subtract(value)
	return secretShares, nil
}

func AdditiveRecoverSecret(shares map[int]ec.Scalar) (ec.Scalar, error) {
	if len(shares) <= 1 {
		return ec.Scalar{}, fmt.Errorf("not enough shares")
	}

	var zn ec.Field
	for _, s := range shares {
		if zn == nil {
			zn = s.Field()
		}
		if !zn.Equals(s.Field()) {
			return ec.Scalar{}, fmt.Errorf("not all shares are from the same finite field")
		}
	}
	if zn == nil {
		return ec.Scalar{}, fmt.Errorf("zn is nil")
	}

	secret := zn.Zero()
	for _, s := range shares {
		secret = secret.Add(s)
	}
	return secret, nil
}
