package ec

import (
	"fmt"
	"sync"
)

var (
	BLS12381 PairingCurve

	pairingCurvesInitialized sync.Once
	pairingCurves            = map[string]PairingCurve{}
)

type Element = Scalar

type PairingCurve interface {
	Name() string
	Equals(o PairingCurve) bool
	E1() Curve
	E2() Curve
	GT() Field
	Pair(a, b Point) (Element, error)
}

func init() {
	initPairingCurves()
}

func initPairingCurves() {
	pairingCurvesInitialized.Do(func() {
		BLS12381 = newBLS12381()
		pairingCurves[BLS12381.Name()] = BLS12381
	})
}

func NewPairingCurve(name string) (PairingCurve, error) {
	curve, exists := pairingCurves[name]
	if !exists {
		return nil, fmt.Errorf("unsupported pairing curve: %s", name)
	}
	return curve, nil
}
