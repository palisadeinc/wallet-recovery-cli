package tsm

import (
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/partialresults/partialsymmetric"
)

// HMACFinalize will construct the final HMAC-SHA256 or HMAC-SHA512 digest by combining data from a list of partial
// HMAC-SHA256 or HMAC-512 results returned from the MPC nodes.
func HMACFinalize(partialResults [][]byte) (ciphertext []byte, err error) {
	ps := make([]partialsymmetric.HMACPartialResult, len(partialResults))
	for i := 0; i < len(partialResults); i++ {
		if err = ps[i].Decode(partialResults[i]); err != nil {
			return nil, fmt.Errorf("unable to decode partial result: %w", err)
		}
	}
	return partialsymmetric.FinalizeHMAC(ps...)
}
