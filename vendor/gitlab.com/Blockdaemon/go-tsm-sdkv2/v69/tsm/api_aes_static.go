package tsm

import (
	"errors"
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/partialresults/partialsymmetric"
)

// AESFinalizeCTR will construct the final AES-CTR key stream by combining data from a list of partial AES-CTR results
// returned from the MPC nodes.
func AESFinalizeCTR(partialResults [][]byte) (keyStream []byte, err error) {
	ps := make([]partialsymmetric.AESCTRPartialResult, len(partialResults))
	for i := 0; i < len(partialResults); i++ {
		if err = ps[i].Decode(partialResults[i]); err != nil {
			return nil, fmt.Errorf("unable to decode partial result: %w", err)
		}
	}
	return partialsymmetric.FinalizeAESCTR(ps...)
}

// AESFinalizeCBCEncrypt will construct the final AES-CBC encryption by combining data from a list of partial AES-CBC
// encrypt results returned from the MPC nodes.
func AESFinalizeCBCEncrypt(partialResults [][]byte) (ciphertext []byte, err error) {
	ps := make([]partialsymmetric.AESCBCEncryptPartialResult, len(partialResults))
	for i := 0; i < len(partialResults); i++ {
		if err = ps[i].Decode(partialResults[i]); err != nil {
			return nil, fmt.Errorf("unable to decode partial result: %w", err)
		}
	}
	return partialsymmetric.FinalizeAESCBCEncrypt(ps...)
}

// AESFinalizeCBCDecrypt will construct the final AES-CBC decryption by combining data from a list of partial AES-CBC
// decrypt results returned from the MPC nodes.
func AESFinalizeCBCDecrypt(partialResults [][]byte) (plaintext []byte, err error) {
	ps := make([]partialsymmetric.AESCBCDecryptPartialResult, len(partialResults))
	for i := 0; i < len(partialResults); i++ {
		if err = ps[i].Decode(partialResults[i]); err != nil {
			return nil, fmt.Errorf("unable to decode partial result: %w", err)
		}
	}
	return partialsymmetric.FinalizeAESCBCDecrypt(ps...)
}

// AESFinalizeGCMEncrypt will construct the final AES-GCM encryption and tag by combining data from a list of partial
// AES-GCM encrypt results returned from the MPC nodes.
func AESFinalizeGCMEncrypt(partialResults [][]byte) (encryptionResult *AESGCMEncryptResult, err error) {
	ps := make([]partialsymmetric.AESGCMEncryptPartialResult, len(partialResults))
	for i := 0; i < len(partialResults); i++ {
		if err = ps[i].Decode(partialResults[i]); err != nil {
			return nil, fmt.Errorf("unable to decode partial result: %w", err)
		}
	}
	ciphertext, tag, err := partialsymmetric.FinalizeAESGCMEncrypt(ps...)
	if err != nil {
		return nil, err
	}
	return &AESGCMEncryptResult{
		Ciphertext: ciphertext,
		Tag:        tag,
	}, nil
}

var ErrMessageAuthenticationFailed = errors.New("message authentication failed")

// AESFinalizeGCMDecrypt will construct the final AES-GCM decryption by combining data from a list of partial AES-GCM
// decrypt results returned from the MPC nodes. ErrMessageAuthenticationFailed is returned if the provided ciphertext
// and additional data are not valid with respect to the provided gcm tag.
func AESFinalizeGCMDecrypt(partialResults [][]byte) (plaintext []byte, err error) {
	ps := make([]partialsymmetric.AESGCMDecryptPartialResult, len(partialResults))
	for i := 0; i < len(partialResults); i++ {
		if err = ps[i].Decode(partialResults[i]); err != nil {
			return nil, fmt.Errorf("unable to decode partial result: %w", err)
		}
	}
	plaintext, err = partialsymmetric.FinalizeAESGCMDecrypt(ps...)
	if errors.Is(err, partialsymmetric.ErrMessageAuthentication) {
		return nil, ErrMessageAuthenticationFailed
	}
	return plaintext, err
}
