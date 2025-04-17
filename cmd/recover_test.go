package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
)

// Secp256k1 implements the secp256k1 elliptic curve parameters
type Secp256k1 struct {
	*elliptic.CurveParams
}

// Secp256k1 curve parameters
func initSecp256k1() Secp256k1 {
	params := &elliptic.CurveParams{
		Name:    "secp256k1",
		BitSize: 256,
		// These parameters are taken from the secp256k1 spec directly
		P: new(big.Int).SetBytes([]byte{
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F,
		}),
		N: new(big.Int).SetBytes([]byte{
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
			0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
			0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
		}),
		B: new(big.Int).SetInt64(7),
		Gx: new(big.Int).SetBytes([]byte{
			0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
			0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
			0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
			0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
		}),
		Gy: new(big.Int).SetBytes([]byte{
			0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65,
			0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
			0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19,
			0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8,
		}),
	}
	return Secp256k1{params}
}

// Marshal an elliptic curve point to the uncompressed form
func marshalUncompressed(curve elliptic.Curve, x, y *big.Int) []byte {
	byteLen := (curve.Params().BitSize + 7) >> 3

	// Uncompressed format: 0x04 || X || Y
	ret := make([]byte, 1+2*byteLen)
	ret[0] = 4 // uncompressed point

	// X and Y coordinates are written in big-endian format
	xBytes := x.Bytes()
	yBytes := y.Bytes()

	// Pad X if needed
	copy(ret[1+byteLen-len(xBytes):1+byteLen], xBytes)

	// Pad Y if needed
	copy(ret[1+2*byteLen-len(yBytes):1+2*byteLen], yBytes)

	return ret
}

func Test_Main(t *testing.T) {
	main()
}

func main() {
	// Private key in base64 format
	privateKeyBase64 := "G6Rm4CK6h5LvgWvqxtyTQeeV9YmH8RkoQhpOLquQEmc="
	privateKeyBytes, err := base64.StdEncoding.DecodeString(privateKeyBase64)
	if err != nil {
		fmt.Println("Error decoding base64 private key:", err)
		return
	}

	// Convert bytes to a big.Int
	privateKeyInt := new(big.Int).SetBytes(privateKeyBytes)

	// Initialize secp256k1 curve
	curve := initSecp256k1()

	// Create a private key object
	privateKey := &ecdsa.PrivateKey{
		D: privateKeyInt,
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
		},
	}

	// Generate the public key from the private key
	privateKey.PublicKey.X, privateKey.PublicKey.Y = curve.ScalarBaseMult(privateKey.D.Bytes())

	// Define the custom OID for secp256k1
	// 1.3.132.0.10 is the OID for secp256k1
	secp256k1OID := asn1.ObjectIdentifier{1, 3, 132, 0, 10}

	// Definition for PKIX public key
	type algorithmIdentifier struct {
		Algorithm asn1.ObjectIdentifier
	}

	type publicKeyInfo struct {
		Algorithm algorithmIdentifier
		PublicKey asn1.BitString
	}

	// Marshal public key to ASN.1 DER format manually
	pubKeyRaw := marshalUncompressed(curve, privateKey.PublicKey.X, privateKey.PublicKey.Y)

	// Create the publicKeyInfo structure
	pkiInfo := publicKeyInfo{
		Algorithm: algorithmIdentifier{
			Algorithm: secp256k1OID,
		},
		PublicKey: asn1.BitString{
			Bytes:     pubKeyRaw,
			BitLength: 8 * len(pubKeyRaw),
		},
	}

	// Marshal the structure to DER format
	publicKeyDER, err := asn1.Marshal(pkiInfo)
	if err != nil {
		fmt.Println("Error marshaling public key:", err)
		return
	}

	// Print the DER formatted public key
	fmt.Println("Public Key (DER format):")
	fmt.Println(hex.EncodeToString(publicKeyDER))

	// Print the raw public key coordinates for verification
	fmt.Println("\nPublic Key X coordinate:")
	fmt.Println(privateKey.PublicKey.X.String())
	fmt.Println("\nPublic Key Y coordinate:")
	fmt.Println(privateKey.PublicKey.Y.String())
}
