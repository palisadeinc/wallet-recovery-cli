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

// NetworkType is which Mina network id to use
type NetworkType byte

const (
	TestNet NetworkType = 0
	MainNet NetworkType = 1
	NullNet NetworkType = 2
)

func Hash(networkID NetworkType, fieldElements []ec.Scalar) (ec.Scalar, error) {
	// Input validation

	for _, f := range fieldElements {
		if !f.Field().Equals(fp) {
			return ec.Scalar{}, errors.New("field element is from the wrong field")
		}
	}

	if networkID != TestNet && networkID != MainNet && networkID != NullNet {
		return ec.Scalar{}, fmt.Errorf("unsupported network: %v", networkID)
	}

	// Init

	once.Do(initPoseidonContexts)

	ctx := new(context)
	ctx.spongeWidth = contexts[0].spongeWidth
	ctx.spongeRate = contexts[0].spongeRate
	ctx.fullRounds = contexts[0].fullRounds
	ctx.roundKeys = contexts[0].roundKeys
	ctx.mdsMatrix = contexts[0].mdsMatrix
	ctx.spongeIv = contexts[0].spongeIv
	ctx.state = make([]ec.Scalar, contexts[0].spongeWidth)
	if networkID != NullNet {
		iv := contexts[0].spongeIv[networkID]
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
			ctx.permute()
			ctx.absorbed = 0
		}
		ctx.state[ctx.absorbed] = ctx.state[ctx.absorbed].Add(f)
		ctx.absorbed++
	}

	// Digest

	ctx.permute()
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
