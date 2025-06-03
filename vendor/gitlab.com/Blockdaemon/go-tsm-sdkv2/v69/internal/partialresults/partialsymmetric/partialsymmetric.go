package partialsymmetric

import (
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/bch"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/bits"
)

type PartialResultType int

const (

	// Simple - each partial contains the value in the clear; integrity is obtained by comparing results
	// Used by the MRZ15 protocol.
	Simple PartialResultType = 1

	// BCH2 - Only two shares. One share consists of the actual result and a BCH mac tag on the result. The other
	// share consists of the corresponding BCH mac key. This format matches the WRK17 protocol, where output is only
	// computed to Bob and where Alice just inputs the mac key.
	BCH2 PartialResultType = 2 //

)

func (s PartialResultType) String() string {
	i := s - 1
	if i < 0 || int(i) >= len(partialResultTypes) {
		return "unknown"
	}
	return partialResultTypes[i]
}

var partialResultTypes = []string{"simple", "bch2"}

func checkExtendedBCH(code *bch.Code, message, bchTag, bchKey bits.BitSet) error {
	if message.Length()%128 != 0 {
		return fmt.Errorf("bch2: message must be a full number of 128-bit blocks")
	}

	blockCount := message.Length() / 128

	if bchTag.Length() != blockCount*code.CodewordSize {
		return fmt.Errorf("bch2: mac tag must be one code word per 128 bit message (msg: %d, tag: %d)", message.Length(), bchTag.Length())
	}

	if bchKey.Length() != blockCount*2*code.CodewordSize {
		return fmt.Errorf("bch2: mac key must be two code words per 128 bit message")
	}

	// Check mac for each 128-bit block of key stream

	macKeySize := 2 * code.CodewordSize
	for i := 0; i < blockCount; i++ {
		msgBlockI := message.Subset(i*128, (i+1)*128)
		tagI := bchTag.Subset(i*code.CodewordSize, (i+1)*code.CodewordSize)
		keyI := bchKey.Subset(i*macKeySize, (i+1)*macKeySize)
		expectedTagI, err := code.InfoMac(msgBlockI, keyI)
		if err != nil {
			return err
		}
		if !expectedTagI.Equal(tagI) {
			return fmt.Errorf("tag mismatch at block %d", i)
		}
	}

	return nil

}
