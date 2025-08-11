package partialsymmetric

import (
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/bits"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/infomac"
)

type PartialResultType int

const (

	// Simple - each partial contains the value in the clear; integrity is obtained by comparing results
	// Used by the MRZ15 protocol.
	Simple PartialResultType = 1

	// MAC2 - Only two shares. One share consists of the actual result and an information theoretical mac tag on the
	// result. The other share consists of the corresponding information theoretical mac key. This format matches the
	// WRK17 protocol, where output is only computed to Bob and where Alice just inputs the mac key.
	MAC2 PartialResultType = 2 //

)

const (

	// SecurityLevelMAC2OutputIntegrity defines the statistical security level used to protect the partial output in the
	// MAC2 partial result type. A security level of 40 is considered enough, assuming that the attacker only gets a
	// single attempt. In other words, we assume that if combining partial results in a security error, then the
	// partial results are discarded, and a new MPC session is run.
	SecurityLevelMAC2OutputIntegrity = 40
)

func (s PartialResultType) String() string {
	i := s - 1
	if i < 0 || int(i) >= len(partialResultTypes) {
		return "unknown"
	}
	return partialResultTypes[i]
}

var partialResultTypes = []string{"simple", "mac2"}

func checkInfoMac(message, tag, key bits.BitSet) error {
	mac := infomac.NewInfoMac(message.Length(), SecurityLevelMAC2OutputIntegrity)
	actualTag := mac.ComputeTag(message, key)
	if !tag.Equal(actualTag) {
		return fmt.Errorf("security error: tag mismatch")
	}
	return nil
}
