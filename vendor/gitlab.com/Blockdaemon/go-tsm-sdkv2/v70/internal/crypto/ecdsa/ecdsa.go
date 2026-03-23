package ecdsa

import (
	"fmt"
	"math/big"

	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/ec"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

var maxSigned32BitValue, _ = new(big.Int).SetString("7FFFFFFF", 16)

type Signature struct {
	curve      ec.Curve
	r, s       ec.Scalar
	recoveryID int
}

func NewSignature(R ec.Point, s ec.Scalar) Signature {
	x, _, err := R.Coordinates()
	if err != nil {
		panic(err)
	}
	s, recoveryID := getSmallestS(s, getRecoveryID(R))

	return Signature{
		curve:      R.Curve(),
		r:          s.Field().NewScalarWithModularReduction(x),
		s:          s,
		recoveryID: recoveryID,
	}
}

func DecodeASN1(sig []byte, curve ec.Curve, recoveryID int) (Signature, error) {
	r, s, err := decodeASN1(sig)
	if err != nil {
		return Signature{}, err
	}
	return Signature{
		curve:      curve,
		r:          curve.Zn().NewScalarWithModularReduction(r),
		s:          curve.Zn().NewScalarWithModularReduction(s),
		recoveryID: recoveryID,
	}, nil
}

func (s Signature) Encode() []byte {
	return s.ASN1()
}

func (s Signature) ASN1() []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(s.r.Value())
		b.AddASN1BigInt(s.s.Value())
	})
	sig, err := b.Bytes()
	if err != nil {
		panic(err)
	}
	return sig
}

func (s Signature) Curve() ec.Curve {
	return s.curve
}

func (s Signature) R() *big.Int {
	return s.r.Value()
}

func (s Signature) S() *big.Int {
	return s.s.Value()
}

func (s Signature) RecoveryID() int {
	return s.recoveryID
}

func Verify(publicKey ec.Point, hash []byte, r, s *big.Int) bool {
	curve := publicKey.Curve()
	zn := curve.Zn()

	if publicKey.IsPointAtInfinity() {
		return false
	}

	if len(hash) != HashLength(curve) {
		return false
	}

	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false
	}
	if r.Cmp(zn.Modulus()) >= 0 || s.Cmp(zn.Modulus()) >= 0 {
		return false
	}

	e := hashToInt(hash, zn)
	w := new(big.Int).ModInverse(s, zn.Modulus())

	u1 := e.Mul(e, w)
	u1.Mod(u1, zn.Modulus())
	u2 := w.Mul(r, w)
	u2.Mod(u2, zn.Modulus())

	x1y1 := curve.G().MultiplyVarTime(zn.NewScalarWithModularReduction(u1))
	x2y2 := publicKey.MultiplyVarTime(zn.NewScalarWithModularReduction(u2))
	x, y, err := x1y1.Add(x2y2).Coordinates()
	if err != nil {
		return false
	}
	if x.Sign() == 0 && y.Sign() == 0 {
		return false
	}
	x.Mod(x, zn.Modulus())
	return x.Cmp(r) == 0
}

func VerifyASN1(publicKey ec.Point, hash, sig []byte) bool {
	r, s, err := decodeASN1(sig)
	if err != nil {
		return false
	}
	return Verify(publicKey, hash, r, s)
}

func NewScalarFromHash(messageHash []byte, field ec.Field) ec.Scalar {
	z := hashToInt(messageHash, field)
	return field.NewScalarWithModularReduction(z)
}

func HashLength(curve ec.Curve) int {
	hashLength := curve.Zn().ByteLen()
	if curve.Equals(ec.P521) {
		hashLength = 64
	}
	return hashLength
}

func getRecoveryID(R ec.Point) int {
	x, y, err := R.Coordinates()
	if err != nil {
		return -1
	}
	recoveryID := new(big.Int).Div(x, R.Curve().Zn().Modulus())
	recoveryID.Lsh(recoveryID, 1)
	if y.Bit(0) == 1 {
		recoveryID.SetBit(recoveryID, 0, 1)
	}

	if recoveryID.Cmp(maxSigned32BitValue) > 0 {
		return -1
	}

	return int(recoveryID.Int64())
}

func getSmallestS(s ec.Scalar, recoveryID int) (ec.Scalar, int) {
	otherS := new(big.Int).Sub(s.Field().Modulus(), s.Value())
	if s.Value().Cmp(otherS) > 0 {
		s = s.Field().NewScalarWithModularReduction(otherS)
		if recoveryID >= 0 {
			recoveryID ^= 1
		}
	}

	return s, recoveryID
}

func decodeASN1(sig []byte) (r, s *big.Int, err error) {
	var inner cryptobyte.String
	var rBytes, sBytes []byte
	input := cryptobyte.String(sig)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(&rBytes) ||
		!inner.ReadASN1Integer(&sBytes) ||
		!inner.Empty() {
		return nil, nil, fmt.Errorf("invalid ASN1 signature")
	}
	return new(big.Int).SetBytes(rBytes), new(big.Int).SetBytes(sBytes), nil
}

func hashToInt(hash []byte, zn ec.Field) *big.Int {
	if zn.Equals(ec.StarkCurve.Zn()) {
		// Enable verification of starknet signatures
		return hashToIntStark(hash)
	}

	orderBits := zn.Modulus().BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

// Starknet interprets FIPS PUB 186.4 section 6.4 in the wrong way, so they end up right shifting the message hash with
// BitLen(BigInt(messageHash))-BitLen(Modulus) instead of BitLen(HashLength)-BitLen(Modulus), which is what Go's ECDSA
// implementation does.
func hashToIntStark(hash []byte) *big.Int {
	if len(hash) > 32 {
		hash = hash[:32]
	}
	ret := new(big.Int).SetBytes(hash)
	excess := ret.BitLen() - ec.StarkCurve.Zn().Modulus().BitLen()
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}
