package minaschnorr

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/base58"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/bits"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/ec"
	"io"
)

// NetworkType is which Mina network ID to use
type NetworkType byte

const (
	TestNet NetworkType = 0
	MainNet NetworkType = 1
	NullNet NetworkType = 2
)

type TransactionType int

const (
	PaymentTransaction    TransactionType = 1
	DelegationTransaction TransactionType = 2
)

func PrepareMessage(message []byte) *SignInput {
	input := NewSignInput(MainNet)
	input.AddBytes(message)
	return input
}

func PrepareRawInput(networkID NetworkType, fieldElements []ec.Scalar, bitVector bits.BitSet) *SignInput {
	input := NewSignInput(networkID)
	for _, fpElement := range fieldElements {
		input.AddFp(fpElement)
	}
	input.bits.SetBitSet(bitVector)
	return input
}

func PrepareTransaction(networkID NetworkType, transactionID TransactionType, fromAddr, toAddr string, fee, amount uint64, nonce, validUntil uint32, memo string) (*SignInput, error) {
	if transactionID != PaymentTransaction && transactionID != DelegationTransaction {
		return nil, fmt.Errorf("unknown transaction type: %d", transactionID)
	}

	feePayerX, feePayerY, err := parseAddress(fromAddr)
	if err != nil {
		return nil, fmt.Errorf("parse error: fee payer address: %v", err)
	}

	sourceX, sourceY := feePayerX, feePayerY

	receiverX, receiverY, err := parseAddress(toAddr)
	if err != nil {
		return nil, fmt.Errorf("parse error: receiver address: %v", err)
	}

	const feeToken = 1
	const tokenID = 1
	tag := [3]bool{false, false, transactionID == DelegationTransaction}

	input := NewSignInput(networkID)

	input.AddFp(feePayerX)
	input.AddFp(sourceX)
	input.AddFp(receiverX)

	input.AddUint64(fee)
	input.AddUint64(feeToken)
	input.AddBit(feePayerY.Value().Bit(0) == 1)
	input.AddUint32(nonce)
	input.AddUint32(validUntil)
	actualMemo := [34]byte{0x01, byte(len(memo))}
	copy(actualMemo[2:], memo)
	input.AddBytes(actualMemo[:])
	for _, b := range tag {
		input.AddBit(b)
	}

	input.AddBit(sourceY.Value().Bit(0) == 1)
	input.AddBit(receiverY.Value().Bit(0) == 1)
	input.AddUint64(tokenID)
	input.AddUint64(amount)
	input.AddBit(false)

	return input, nil
}

type SignInput struct {
	networkID NetworkType
	elements  []ec.Scalar
	bits      bits.BitSet
}

var conv = map[bool]bits.Bit{
	true:  bits.True,
	false: bits.False,
}

func NewSignInput(networkID NetworkType) *SignInput {
	return &SignInput{
		networkID: networkID,
		elements:  []ec.Scalar{},
		bits:      bits.NewZeroSet(0),
	}
}

func (s *SignInput) Clone() *SignInput {
	t := new(SignInput)
	t.networkID = s.networkID
	t.elements = make([]ec.Scalar, len(s.elements))
	copy(t.elements, s.elements)
	t.bits = s.bits.Clone()
	return t
}

func (s *SignInput) AddFp(fpElement ec.Scalar) {
	if !fp.Equals(fpElement.Field()) {
		panic("AddFp: element not from Fp")
	}
	s.elements = append(s.elements, fpElement)
}

func (s *SignInput) AddFq(fqElement ec.Scalar) {
	if !fq.Equals(fqElement.Field()) {
		panic("AddFp: element not from Fp")
	}
	// Mina handles fields as 255 bit numbers, so with each field we lose a bit
	v := fqElement.Value()
	for i := 0; i < 255; i++ {
		b := v.Bit(i)
		s.bits.Append(bits.Bit(b))
	}
}

func (s *SignInput) AddBit(b bool) {
	s.bits.Append(conv[b])
}

func (s *SignInput) AddBytes(input []byte) {
	for _, b := range input {
		for i := 0; i < 8; i++ {
			s.bits.Append(bits.Bit(byte((b >> i) & 1)))
		}
	}
}

func (s *SignInput) AddUint32(x uint32) {
	for i := 0; i < 32; i++ {
		s.bits.Append(bits.Bit(byte((x >> i) & 1)))
	}
}

func (s *SignInput) AddUint64(x uint64) {
	for i := 0; i < 64; i++ {
		s.bits.Append(bits.Bit(byte((x >> i) & 1)))
	}
}

func (s *SignInput) Bytes() []byte {
	res := bits.NewZeroSet(0)
	// Mina handles fields as 255 bit numbers, so with each field we lose a bit
	for _, f := range s.elements {
		v := f.Value()
		for i := 0; i < 255; i++ {
			b := v.Bit(i)
			res.Append(bits.Bit(b))
		}
	}
	for i := 0; i < s.bits.Length(); i++ {
		res.Append(s.bits.Get(i))
	}
	return res.Bytes()
}

func (s *SignInput) FieldElements() []ec.Scalar {
	elements := append([]ec.Scalar{}, s.elements...)

	const chunkSize = 254
	bitVector := s.bits.Clone()
	for bitVector.Length()%chunkSize != 0 {
		bitVector.Append(bits.Bit(0))
	}

	for bitsProcessed := 0; bitsProcessed < bitVector.Length(); bitsProcessed += chunkSize {
		b := bitVector.Subset(bitsProcessed, bitsProcessed+chunkSize).Bytes()
		ec.ReverseSlice(b)
		f, err := fp.DecodeScalar(b)
		if err != nil {
			// Since we process 254 bits at a time, it will always be an element of Fp
			panic(fmt.Sprintf("error decoding chunk as Fp element: %v", err))
		}
		elements = append(elements, f)
	}
	return elements
}

func (s *SignInput) Encode() []byte {
	out := &bytes.Buffer{}
	_ = writeBytes(out, []byte("MinaSchnorr"))
	_ = writeBytes(out, []byte{byte(s.networkID)})
	_ = binary.Write(out, binary.BigEndian, uint32(len(s.elements)*fp.ByteLen()))
	for _, fe := range s.elements {
		out.Write(fe.Encode())
	}
	_ = writeBytes(out, s.bits.Serialize())
	return out.Bytes()

}

func (s *SignInput) Decode(input []byte) error {
	var (
		tmpBytes []byte
		err      error
	)

	// Type ID

	if tmpBytes, err = readBytes(&input); err != nil {
		return err
	}
	if !bytes.Equal(tmpBytes, []byte("MinaSchnorr")) {
		return fmt.Errorf("invalid type")
	}

	// Network ID

	if tmpBytes, err = readBytes(&input); err != nil {
		return err
	}
	if len(tmpBytes) != 1 {
		return fmt.Errorf("invalid network ID length: %d", len(tmpBytes))
	}
	s.networkID = NetworkType(tmpBytes[0])

	// Field elements

	if tmpBytes, err = readBytes(&input); err != nil {
		return err
	}
	elementCount := len(tmpBytes) / fp.ByteLen()
	if len(tmpBytes) != elementCount*fp.ByteLen() {
		return fmt.Errorf("invalid field elements length")
	}
	s.elements = make([]ec.Scalar, 0, elementCount)
	for i := 0; i < elementCount; i++ {
		fieldElement, err := fp.DecodeScalar(tmpBytes[:fp.ByteLen()])
		if err != nil {
			return fmt.Errorf("invalid field element: %v", err)
		}
		s.elements = append(s.elements, fieldElement)
		tmpBytes = tmpBytes[fp.ByteLen():]
	}

	// Bit vector

	if tmpBytes, err = readBytes(&input); err != nil {
		return err
	}
	if s.bits, err = bits.Deserialize(tmpBytes); err != nil {
		return fmt.Errorf("invalid bit vector: %v", err)
	}

	return nil
}

func writeBytes(output io.Writer, data []byte) error {
	if err := binary.Write(output, binary.BigEndian, uint32(len(data))); err != nil {
		return err
	}
	_, err := output.Write(data)
	return err
}

func readBytes(input *[]byte) ([]byte, error) {
	data := *input
	if len(data) < 4 {
		return nil, io.ErrUnexpectedEOF
	}
	payloadLength := (int)(binary.BigEndian.Uint32(data) & 0x7FFFFFFF)
	if len(data) < 4+payloadLength {
		return nil, io.ErrUnexpectedEOF
	}
	res := data[4 : 4+payloadLength]
	*input = (*input)[4+payloadLength:]
	return res, nil
}

func parseAddress(b58Address string) (x, y ec.Scalar, err error) {
	const version = 0xcb
	const nonZeroCurvePointVersion = 0x01
	const isCompressed = 0x01

	buffer, err := base58.Decode(b58Address)
	if err != nil {
		return ec.Scalar{}, ec.Scalar{}, err
	}
	if len(buffer) != 40 {
		return ec.Scalar{}, ec.Scalar{}, fmt.Errorf("invalid byte sequence")
	}
	if buffer[0] != version {
		return ec.Scalar{}, ec.Scalar{}, fmt.Errorf("invalid version")
	}
	if buffer[1] != nonZeroCurvePointVersion {
		return ec.Scalar{}, ec.Scalar{}, fmt.Errorf("invalid non-zero curve point version")
	}
	if buffer[2] != isCompressed {
		return ec.Scalar{}, ec.Scalar{}, fmt.Errorf("invalid compressed flag")
	}
	hash1 := sha256.Sum256(buffer[:36])
	hash2 := sha256.Sum256(hash1[:])
	if subtle.ConstantTimeCompare(hash2[:4], buffer[36:40]) != 1 {
		return ec.Scalar{}, ec.Scalar{}, fmt.Errorf("invalid checksum")
	}
	rawPublicKey := buffer[3:35]
	rawPublicKey[31] |= buffer[35] << 7

	publicKey, err := ec.PallasMina.DecodePoint(rawPublicKey, true)
	if err != nil {
		return ec.Scalar{}, ec.Scalar{}, fmt.Errorf("invalid public key: %v", err)
	}

	x, y = pointCoordinates(publicKey)
	return x, y, nil
}
