package tsm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/ec"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/schnorrvariant"
	"io"
	"net/http"
	"regexp"
)

func marshalJSON(val interface{}) (io.Reader, error) {
	buf, err := json.Marshal(val)
	if err != nil {
		return nil, toTSMError(fmt.Errorf("error creating JSON: %w", err), ErrOperationFailed)
	}

	return bytes.NewReader(buf), nil
}

func unmarshalJSON(reader io.Reader, val interface{}) error {
	err := json.NewDecoder(reader).Decode(val)
	if err != nil {
		return toTSMError(fmt.Errorf("error parsing JSON: %w", err), ErrOperationFailed)
	}
	return nil
}

func closeResponseBody(response *http.Response) {
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
}

var allowedCharsInKeyID = regexp.MustCompile(`^[a-zA-Z0-9_\-]+$`).MatchString

func validateKeyID(keyID string) error {
	if keyID == "" {
		return fmt.Errorf("key ID is empty")
	}
	if len(keyID) > 28 {
		return fmt.Errorf("key ID must not be longer than 28 characters, but it was %d", len(keyID))
	}
	if !allowedCharsInKeyID(keyID) {
		return fmt.Errorf("key ID contains invalid characters: %s", keyID)
	}
	return nil
}

func validateSchnorrVariant(schnorrVariant string) (ec.Curve, error) {
	if schnorrVariant == "" {
		return nil, fmt.Errorf("schnorr variant is empty")
	}
	curve, err := schnorrvariant.VariantToCurve(schnorrVariant)
	if err != nil {
		return nil, fmt.Errorf("unsupported schnorr variant: %s", schnorrVariant)
	}
	return curve, nil
}

type ecPublicKey struct {
	Scheme string `json:"scheme"`
	Curve  string `json:"curve"`
	Point  []byte `json:"point"`
	value  ec.Point
}

func newECPublicKey(scheme, curveName string, point []byte) (*ecPublicKey, error) {
	P, err := validateECPoint(scheme, curveName, point)
	if err != nil {
		return nil, err
	}
	return &ecPublicKey{
		Scheme: scheme,
		Curve:  P.Curve().Name(),
		Point:  P.Encode(),
		value:  P,
	}, nil
}

func (s *ecPublicKey) Encode() []byte {
	data, err := json.Marshal(s)
	if err != nil {
		panic(fmt.Errorf("failed to marshall EC public key: %w", err))
	}
	return data
}

func (s *ecPublicKey) isECDSA() bool {
	return s.Scheme == "ECDSA"
}

func (s *ecPublicKey) isSchnorr() bool {
	_, err := schnorrvariant.VariantToCurve(s.Scheme)
	return err == nil
}

func decodeECPublicKey(data []byte) (*ecPublicKey, error) {
	var publicKey ecPublicKey
	if err := json.Unmarshal(data, &publicKey); err != nil {
		return nil, fmt.Errorf("failed to unmarshall EC public key: %w", err)
	}
	P, err := validateECPoint(publicKey.Scheme, publicKey.Curve, publicKey.Point)
	if err != nil {
		return nil, err
	}
	publicKey.Curve = P.Curve().Name()
	publicKey.value = P
	return &publicKey, nil
}

func validateECPoint(scheme, curveName string, point []byte) (ec.Point, error) {
	var curve ec.Curve
	switch scheme {
	case "ECDSA":
		var err error
		curve, err = ec.NewCurve(curveName)
		if err != nil {
			return ec.Point{}, err
		}
	case SchnorrEd25519, SchnorrEd448, SchnorrBIP340, SchnorrMina, SchnorrZilliqa, SchnorrSr25519:
		var err error
		curve, err = schnorrvariant.VariantToCurve(scheme)
		if err != nil {
			return ec.Point{}, err
		}
		if curveName != "" && curveName != curve.Name() {
			return ec.Point{}, fmt.Errorf("invalid curve %s for scheme %s", curveName, scheme)
		}
	default:
		return ec.Point{}, fmt.Errorf("unsupported scheme: %s", scheme)
	}

	P, err := curve.DecodePoint(point, true)
	if err != nil {
		return ec.Point{}, fmt.Errorf("invalid public key for scheme %s: %w", scheme, err)
	}
	return P, nil
}
