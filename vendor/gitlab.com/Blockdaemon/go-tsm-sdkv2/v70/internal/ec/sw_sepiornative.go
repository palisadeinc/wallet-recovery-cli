//go:build extlib

package ec

/*
#cgo CFLAGS: -Ofast
#cgo LDFLAGS: -lcrypto
#include "pointopenssl.h"
*/
import "C"
import (
	"fmt"
	"runtime"
	"unsafe"
)

var cgoChan = make(chan struct{}, runtime.GOMAXPROCS(0))

func (c swCurve) pointAdd(p, q interface{}) interface{} {
	if !c.hasNativeImpl {
		return c.pointAddGeneric(p, q)
	}
	pp := toBytes(p)
	qq := toBytes(q)
	out := make([]byte, 2*c.params.pLen)

	nOut := (*C.uchar)(unsafe.Pointer(&out[0]))
	nOutLength := C.uint(len(out))
	nP1 := (*C.uchar)(unsafe.Pointer(&pp[0]))
	nP1Length := C.uint(len(pp))
	nP2 := (*C.uchar)(unsafe.Pointer(&qq[0]))
	nP2Length := C.uint(len(qq))
	nNID := C.uint(c.params.id)

	cgoChan <- struct{}{}
	result := int(C.point_add(nOut, nOutLength, nP1, nP1Length, nP2, nP2Length, nNID))
	<-cgoChan
	if result < 0 {
		panic("addition error: " + fmt.Sprintf("%d", result))
	}
	if result != 2*c.params.pLen {
		panic("addition error: unexpected length")
	}

	return out
}

func (c swCurve) pointMultiplyInner(p interface{}, e []byte, basePoint, constantTime bool) interface{} {
	if !c.hasNativeImpl {
		return c.pointMultiplyGeneric(p, e, basePoint, constantTime)
	}
	out := make([]byte, 2*c.params.pLen)

	pp := toBytes(p)
	nP := (*C.uchar)(unsafe.Pointer(&pp[0]))
	nPLength := C.uint(len(pp))
	nOut := (*C.uchar)(unsafe.Pointer(&out[0]))
	nOutLength := C.uint(len(out))
	nE := (*C.uchar)(unsafe.Pointer(&e[0]))
	nELength := C.uint(len(e))
	nNID := C.uint(c.params.id)
	nConstantTime := C.bool(constantTime)
	nBasePoint := C.bool(basePoint)

	cgoChan <- struct{}{}
	result := int(C.point_multiply(nOut, nOutLength, nP, nPLength, nE, nELength, nNID, nBasePoint, nConstantTime))
	<-cgoChan
	if result < 0 {
		panic("multiplication error: " + fmt.Sprintf("%d", result))
	}
	if result != 2*c.params.pLen {
		panic("multiplication error: unexpected length")
	}

	return out
}
