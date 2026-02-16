package transport

// ProtocolName is a unique identifier of a given MPC protocol.
//
// For example, DKLS19 refers to an MPC protocol used to compute threshold ECDSA signatures.
type ProtocolName int

const (
	DISABLED   ProtocolName = 0
	SEPH18S    ProtocolName = 2
	SEPD19S    ProtocolName = 3
	SEPD20ECDH ProtocolName = 4
	WRK17      ProtocolName = 6
	MRZ15      ProtocolName = 9
	DKLS19     ProtocolName = 10
	BROADCAST  ProtocolName = 11
	ADN06      ProtocolName = 12
	PKCS11     ProtocolName = 13
	DKLS23     ProtocolName = 14
)

func (p ProtocolName) String() string {
	switch p {
	case DISABLED:
		return "N/A"
	case SEPH18S:
		return "SEPH18S"
	case SEPD19S:
		return "SEPD19S"
	case SEPD20ECDH:
		return "SEPD20ECDH"
	case WRK17:
		return "WRK17"
	case MRZ15:
		return "MRZ15"
	case DKLS19:
		return "DKLS19"
	case BROADCAST:
		return "BROADCAST"
	case ADN06:
		return "ADN06"
	case PKCS11:
		return "PKCS11"
	case DKLS23:
		return "DKLS23"
	default:
		return "N/A"
	}
}
