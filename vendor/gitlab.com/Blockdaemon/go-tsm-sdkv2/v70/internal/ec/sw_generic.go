//go:build !extlib

package ec

func (c swCurve) pointAdd(p, q interface{}) interface{} {
	return c.pointAddGeneric(p, q)
}

func (c swCurve) pointMultiplyInner(p interface{}, e []byte, basePoint, constantTime bool) interface{} {
	return c.pointMultiplyGeneric(p, e, basePoint, constantTime)
}
