package secretshare

import (
	"bytes"
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/random"
	"sort"
)

type XORReplicatedShare struct {

	// For (3,1), ReplicatedShares[0] is player's own share, and ReplicatedShares[1] is previous player's share
	ReplicatedShares [][]byte
}

func (k XORReplicatedShare) KeyLength() int {
	return len(k.ReplicatedShares[0])
}

func (k XORReplicatedShare) Equals(k2 XORReplicatedShare) bool {
	if len(k.ReplicatedShares) != len(k2.ReplicatedShares) {
		return false
	}
	for i, s := range k.ReplicatedShares {
		if !bytes.Equal(k2.ReplicatedShares[i], s) {
			return false
		}
	}
	return true
}

func XORReplicatedSecretShare(players []int, threshold int, key []byte) (shares map[int]XORReplicatedShare, err error) {
	sortedPlayers := make([]int, len(players))
	copy(sortedPlayers, players)
	sort.Ints(sortedPlayers)

	if threshold != 1 {
		return nil, fmt.Errorf("only threshold 1 supported")
	}
	if len(sortedPlayers) != 3 {
		return nil, fmt.Errorf("invalid players (must be three unique integers)")
	}

	// Create xor sharing of key

	keyLength := len(key)
	s := make([][]byte, 3)
	s[0] = make([]byte, keyLength)
	copy(s[0], key)
	s[1] = random.Bytes(keyLength)
	s[2] = random.Bytes(keyLength)
	for i := 0; i < keyLength; i++ {
		s[0][i] ^= s[1][i]
	}
	for i := 0; i < keyLength; i++ {
		s[0][i] ^= s[2][i]
	}

	// Each player gets one xor share and the "previous" player gets a copy

	shares = make(map[int]XORReplicatedShare)
	for i, p := range sortedPlayers {
		shares[p] = XORReplicatedShare{
			ReplicatedShares: make([][]byte, 2),
		}
		shares[p].ReplicatedShares[0] = s[i]

		previousI := i - 1
		if previousI < 0 {
			previousI += 3
		}
		shares[p].ReplicatedShares[1] = make([]byte, keyLength)
		copy(shares[p].ReplicatedShares[1], s[previousI])

	}

	return shares, nil

}

func XORReplicatedValidateShare(share XORReplicatedShare) error {
	if len(share.ReplicatedShares) != 2 {
		return fmt.Errorf("not a (3,1) replicated sharing")
	}
	if len(share.ReplicatedShares[0]) != len(share.ReplicatedShares[1]) {
		return fmt.Errorf("replicated share length mismatch: player share length %d; previous player share length %d", len(share.ReplicatedShares[0]), len(share.ReplicatedShares[1]))
	}

	return nil
}

func XORReplicatedRecoverSecret(shares map[int]XORReplicatedShare) (key []byte, err error) {
	if len(shares) != 3 {
		return nil, fmt.Errorf("only (3,1) replicated shares supported")
	}

	for player, share := range shares {
		err := XORReplicatedValidateShare(share)
		if err != nil {
			return nil, fmt.Errorf("invalid share for player %d: %w", player, err)
		}

		// Check that previous player holds a replication of the players primary share

		previousShare := previousShare(player, shares)
		if !bytes.Equal(share.ReplicatedShares[1], previousShare.ReplicatedShares[0]) {
			return nil, fmt.Errorf("inconsistent replicated sharing")
		}

		// Compute the key as the xor of all players' primary share

		if key == nil {
			key = make([]byte, len(share.ReplicatedShares[0]))
			copy(key, share.ReplicatedShares[0])
			continue
		}

		for i, kb := range share.ReplicatedShares[0] {
			key[i] ^= kb
		}

	}

	return key, nil
}

func previousShare(playerIndex int, shares map[int]XORReplicatedShare) XORReplicatedShare {
	playerIndices := make([]int, len(shares))
	i := 0
	for k := range shares {
		playerIndices[i] = k
		i++
	}
	sort.Ints(playerIndices)

	dense := make(map[int]int, len(playerIndices))
	sparse := make(map[int]int, len(playerIndices))
	p := 0
	for _, i := range playerIndices {
		dense[i] = p
		sparse[p] = i
		p++
	}

	densePlayerIndex := dense[playerIndex]
	previousDenseIndex := densePlayerIndex - 1
	if previousDenseIndex < 0 {
		previousDenseIndex += len(shares)
	}
	previousSparseIndex := sparse[previousDenseIndex]

	return shares[previousSparseIndex]
}
