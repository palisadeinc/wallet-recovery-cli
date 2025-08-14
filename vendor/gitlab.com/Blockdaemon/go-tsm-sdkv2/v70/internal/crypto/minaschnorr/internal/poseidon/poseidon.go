package poseidon

import (
	"errors"
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/ec"
	"math/big"
)

var (
	fp = ec.PallasMinaFp
	fq = ec.PallasMina.Zn()
)

// Permutation is the permute function to use
type Permutation uint32

const (
	ThreeW Permutation = 0
	FiveW  Permutation = 1
	Three  Permutation = 2
)

// NetworkType is which Mina network id to use
type NetworkType byte

const (
	TestNet NetworkType = 0
	MainNet NetworkType = 1
	NullNet NetworkType = 2
)

func Hash(permutationType Permutation, networkID NetworkType, fieldElements []ec.Scalar) (ec.Scalar, error) {
	// Input validation

	for _, f := range fieldElements {
		if !f.Field().Equals(fp) {
			return ec.Scalar{}, errors.New("field element is from the wrong field")
		}
	}

	if permutationType != ThreeW && permutationType != FiveW && permutationType != Three {
		return ec.Scalar{}, fmt.Errorf("unsupported permutation type: %v", permutationType)
	}

	if networkID != TestNet && networkID != MainNet && networkID != NullNet {
		return ec.Scalar{}, fmt.Errorf("unsupported network: %v", networkID)
	}

	// Init

	once.Do(initPoseidonContexts)

	ctx := new(context)
	ctx.pType = permutationType
	ctx.spongeWidth = contexts[permutationType].spongeWidth
	ctx.spongeRate = contexts[permutationType].spongeRate
	ctx.fullRounds = contexts[permutationType].fullRounds
	ctx.sBox = contexts[permutationType].sBox
	ctx.roundKeys = contexts[permutationType].roundKeys
	ctx.mdsMatrix = contexts[permutationType].mdsMatrix
	ctx.spongeIv = contexts[permutationType].spongeIv
	ctx.state = make([]ec.Scalar, contexts[permutationType].spongeWidth)
	if networkID != NullNet {
		iv := contexts[permutationType].spongeIv[networkID]
		copy(ctx.state, iv)
	} else {
		for i := range ctx.state {
			ctx.state[i] = fp.Zero()
		}
	}
	ctx.absorbed = 0

	// Update

	for _, f := range fieldElements {
		if ctx.absorbed == ctx.spongeRate {
			ctx.permute(permutationType)
			ctx.absorbed = 0
		}
		ctx.state[ctx.absorbed] = ctx.state[ctx.absorbed].Add(f)
		ctx.absorbed++
	}

	// Digest

	ctx.permute(permutationType)
	res := ctx.state[0].Value()
	return fq.NewScalarWithModularReduction(res), nil
}

func decodeFieldElement(f ec.Field, limbs [4]uint64) ec.Scalar {
	var v, tmp big.Int

	tmp.SetUint64(limbs[3]).Lsh(&tmp, 3*64)
	v.Or(&v, &tmp)
	tmp.SetUint64(limbs[2]).Lsh(&tmp, 2*64)
	v.Or(&v, &tmp)
	tmp.SetUint64(limbs[1]).Lsh(&tmp, 64)
	v.Or(&v, &tmp)
	tmp.SetUint64(limbs[0])
	v.Or(&v, &tmp)

	return f.NewScalarWithModularReduction(&v)
}
