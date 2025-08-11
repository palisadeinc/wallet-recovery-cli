package secretshare

import (
	"bytes"
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/bits"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/infomac"
)

type XORBedozaShare struct {
	KeyShare []byte         // The player's own xor key share, as obtained from BitSet.Serialize()
	MACKeys  map[int][]byte // The keys used to produce a tag on each of the other players' key share, as obtained from BitSet.Serialize()
	MACTags  map[int][]byte // A tag on the player's own key share for each of the other players, as obtained from BitSet.Serialize()
}

func (k XORBedozaShare) KeyLength() int {
	ks, err := bits.Deserialize(k.KeyShare)
	if err != nil {
		panic("bad key share")
	}
	return ks.Length() / 8
}

func (k XORBedozaShare) GetKeyShare() bits.BitSet {
	ks, err := bits.Deserialize(k.KeyShare)
	if err != nil {
		panic("bad key share")
	}
	return ks
}

func (k XORBedozaShare) GetMacKeys() map[int]bits.BitSet {
	macKeys := make(map[int]bits.BitSet)
	for player, macKeyBytes := range k.MACKeys {
		mk, err := bits.Deserialize(macKeyBytes)
		if err != nil {
			panic(fmt.Sprintf("bad mac key for player %d", player))
		}
		macKeys[player] = mk
	}
	return macKeys
}

func (k XORBedozaShare) GetMacTags() map[int]bits.BitSet {
	macTags := make(map[int]bits.BitSet)
	for player, macTagBytes := range k.MACTags {
		mk, err := bits.Deserialize(macTagBytes)
		if err != nil {
			panic(fmt.Sprintf("bad mac tag for player %d", player))
		}
		macTags[player] = mk
	}
	return macTags
}

func (k XORBedozaShare) Equals(k2 XORBedozaShare) bool {
	if !bytes.Equal(k.KeyShare, k2.KeyShare) {
		return false
	}

	if len(k.MACKeys) != len(k2.MACKeys) {
		return false
	}

	if len(k.MACTags) != len(k2.MACTags) {
		return false
	}

	for p, mk := range k.MACKeys {
		mk2, ok := k2.MACKeys[p]
		if !ok {
			return false
		}
		if !bytes.Equal(mk, mk2) {
			return false
		}
	}

	for p, mt := range k.MACKeys {
		mt2, ok := k2.MACKeys[p]
		if !ok {
			return false
		}
		if !bytes.Equal(mt, mt2) {
			return false
		}
	}

	return true
}

func NewXORBedozaShare(keyShare bits.BitSet, macKeys, macTags map[int]bits.BitSet) XORBedozaShare {
	if keyShare.Length()%8 != 0 {
		panic("key shares must be full number of bits")
	}

	macKeyBytes := make(map[int][]byte, len(macKeys))
	for player, macKey := range macKeys {
		macKeyBytes[player] = macKey.Serialize()
	}

	macTagBytes := make(map[int][]byte, len(macKeys))
	for player, macTag := range macTags {
		macTagBytes[player] = macTag.Serialize()
	}

	keyShareBytes := keyShare.Serialize()

	return XORBedozaShare{
		KeyShare: keyShareBytes,
		MACKeys:  macKeyBytes,
		MACTags:  macTagBytes,
	}
}

func XORBedozaSecretShare(players []int, threshold int, key []byte, mac infomac.InfoMac) (shares map[int]XORBedozaShare, err error) {
	if len(players) != 2 || threshold != 1 {
		return nil, fmt.Errorf("invalid number of players and threshold")
	}

	// Generate random sharing of the key

	k := bits.NewFromBytes(key)

	keyShares := make(map[int]bits.BitSet)
	k0 := bits.NewZeroSet(k.Length())
	k0.Xor(k)
	for i := 1; i < len(players); i++ {
		r := bits.NewRandomSet(k.Length())
		keyShares[players[i]] = r
		k0.Xor(r)
	}
	keyShares[players[0]] = k0

	// Generate random mac keys (bedoza style; each player holds a mac key for each of the other players)

	macKeySize := mac.GetKeySize(k)

	macKeys := make(map[int]map[int]bits.BitSet)
	for i := 0; i < len(players); i++ {
		macKeys[players[i]] = make(map[int]bits.BitSet)
		for j := 0; j < len(players); j++ {
			if j == i {
				continue
			}
			macKeys[players[i]][players[j]] = bits.NewRandomSet(macKeySize)
		}
	}

	// Compute mac tags (bedoza style; each player holds a tag for each of the other players)

	macTags := make(map[int]map[int]bits.BitSet)
	for i := 0; i < len(players); i++ {
		macTags[players[i]] = make(map[int]bits.BitSet)
		for j := 0; j < len(players); j++ {
			if j == i {
				continue
			}
			keyShare := keyShares[players[i]]
			macKey := macKeys[players[j]][players[i]]
			tag := mac.ComputeTag(keyShare, macKey)
			macTags[players[i]][players[j]] = tag
		}
	}

	res := make(map[int]XORBedozaShare)
	for i := range players {
		res[players[i]] = NewXORBedozaShare(keyShares[players[i]], macKeys[players[i]], macTags[players[i]])
	}

	return res, nil
}

func (s XORBedozaShare) Validate(expectedKeySize, playerIndex int, mac infomac.InfoMac) (err error) {
	ks, err := bits.Deserialize(s.KeyShare)
	if err != nil {
		return fmt.Errorf("bad key share: %w", err)
	}

	dummyKey := bits.NewZeroSet(expectedKeySize)
	expectedMacKeySize := mac.GetKeySize(dummyKey)
	expectedMacTagSize := mac.GetTagSize(dummyKey)

	if ks.Length() != expectedKeySize {
		return fmt.Errorf("only %d-bit key sharing supported currently, but was %d", expectedKeySize, ks.Length())
	}

	if len(s.MACKeys) != 1 {
		return fmt.Errorf("only (2,1) bedoza sharings currently supported, but found %d mac keys", len(s.MACKeys))
	}

	var otherPlayerIndex int
	for p, macKeyBytes := range s.MACKeys {
		if p == playerIndex {
			return fmt.Errorf("mac key player should be other player")
		}
		otherPlayerIndex = p
		k, err := bits.Deserialize(macKeyBytes)
		if err != nil {
			return fmt.Errorf("bad mac key for player %d: %w", p, err)
		}
		if k.Length() != expectedMacKeySize {
			return fmt.Errorf("bad mac key bit size for player %d: expected %d but was %d", p, expectedMacKeySize, k.Length())
		}
	}

	if len(s.MACTags) != 1 {
		return fmt.Errorf("only (2,1) bedoza sharings currently supported, but found %d mac tags", len(s.MACTags))

	}
	for p, tag := range s.MACTags {
		if p != otherPlayerIndex {
			return fmt.Errorf("mac key player should be other player")
		}
		t, err := bits.Deserialize(tag)
		if err != nil {
			return fmt.Errorf("bad mac tag for player %d: %w", p, err)
		}
		if t.Length() != expectedMacTagSize {
			return fmt.Errorf("bad mac tag bit size for player %d: expected %d but was %d", p, expectedMacTagSize, t.Length())
		}
	}

	return nil
}

func XORBedozaRecoverSecret(mac infomac.InfoMac, sharing map[int]XORBedozaShare) (key []byte, err error) {
	if len(sharing) != 2 {
		return nil, fmt.Errorf("only (2,1) bedoza shares supported")
	}

	var keyBitSize int
	for _, share := range sharing {
		keyBitSize = share.KeyLength() * 8
		break
	}

	// Validate all macs on the key shares

	for player, share := range sharing {
		err := share.Validate(keyBitSize, player, mac)
		if err != nil {
			return nil, fmt.Errorf("invalid share for player %d: %w", player, err)
		}

		keyShare := share.GetKeyShare()

		for otherPlayer := range share.MACKeys {
			macKeyBytes, exists := sharing[otherPlayer].MACKeys[player]
			if !exists {
				return nil, fmt.Errorf("player %d did not have a mac key for player %d share", otherPlayer, player)
			}

			macKey, err := bits.Deserialize(macKeyBytes)
			if err != nil {
				return nil, err
			}

			macTagBytes := share.MACTags[otherPlayer]
			macTag, err := bits.Deserialize(macTagBytes)
			if err != nil {
				return nil, err
			}

			if macKey.Length() != mac.GetKeySize(keyShare) {
				return nil, fmt.Errorf("invalid mac key length (expected %d bits, got %d)", mac.GetKeySize(keyShare), macKey.Length())
			}
			expectedTag := mac.ComputeTag(keyShare, macKey)

			if !macTag.Equal(expectedTag) {
				return nil, fmt.Errorf("invalid sharing: mac tag was invalid")
			}

		}

	}

	// Recombine the key from the key shares

	k := bits.NewZeroSet(keyBitSize)
	for _, share := range sharing {
		k.Xor(share.GetKeyShare())
	}

	return k.Bytes(), nil
}
