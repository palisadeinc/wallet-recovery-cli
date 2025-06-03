package transport

// ProtocolName is a unique identifier of a given MPC protocol.
//
// For example, DKLS19 refers to an MPC protocol used to compute threshold ECDSA signatures.
type ProtocolName int

const (
	DISABLED ProtocolName = iota
	DKLS18
	SEPH18S
	SEPD19S
	SEPD20ECDH
	SEPH20RSA
	WRK17
	SEPH15PRF
	XORSHARE
	MRZ15
	DKLS19
	BROADCAST
	ADN06
	PKCS11
)

// String returns a string representation of the given protocol name.
func (p ProtocolName) String() string {
	return [...]string{
		"N/A",
		"DKLS18",
		"SEPH18S",
		"SEPD19S",
		"SEPD20ECDH",
		"SEPH20RSA",
		"WRK17",
		"SEPH15PRF",
		"XORSHARE",
		"MRZ15",
		"DKLS19",
		"BROADCAST",
		"ADN06",
		"PKCS11"}[p]
}
