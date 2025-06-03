package secretshare

import (
	"bytes"
	"crypto/rsa"
	"encoding/gob"
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/combination"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/random"
	"math/big"
	"sort"
)

type RSAKeyShare struct {
	Sharing   SharingType
	N         *big.Int
	E         *big.Int
	Threshold int
	Entries   []RSAKeyShareEntry
}

type RSAKeyShareEntry struct {
	Players []int
	Di      *big.Int
	DPublic *big.Int
}

func (r *RSAKeyShare) Encode() []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(r)
	if err != nil {
		panic(fmt.Sprintf("error encoding RSA share: %s", err))
	}
	return buf.Bytes()
}

func (r *RSAKeyShare) Decode(b []byte) error {
	dec := gob.NewDecoder(bytes.NewBuffer(b))
	return dec.Decode(r)
}

// RSASecretShare will create key shares of an RSA private key for the given players.
// The shares will follow the format from ADN06 (https://iacr.org/archive/eurocrypt2006/40040601/40040601.pdf)
func RSASecretShare(players []int, threshold int, privateKey *rsa.PrivateKey) (map[int]RSAKeyShare, error) {
	if threshold <= 0 {
		return nil, fmt.Errorf("invalid threshold: %d", threshold)
	}
	if len(players) <= threshold {
		return nil, fmt.Errorf("threshold must be less than the number of players")
	}

	limit1, limit2 := diLimits(threshold+1, privateKey)
	rsaKeyShares := map[int]RSAKeyShare{}

	combinationCount := combination.NumberOfCombinations(len(players), threshold+1)
	i := big.NewInt(0)
	for {
		if i.Cmp(combinationCount) == 0 {
			break
		}
		playersSubset := combination.Combination(len(players), threshold+1, i)
		for j, k := range playersSubset {
			playersSubset[j] = players[k]
		}
		sort.Ints(playersSubset)

		keyShares := rsaSecretShare(playersSubset, privateKey, limit1, limit2)
		for j, keyShare := range keyShares {
			playerIndex := playersSubset[j]
			rsaKeyShare, rsaKeyShareExists := rsaKeyShares[playerIndex]
			if !rsaKeyShareExists {
				rsaKeyShare.Sharing = ADN06Sharing
				rsaKeyShare.N = privateKey.N
				rsaKeyShare.E = big.NewInt(int64(privateKey.E))
				rsaKeyShare.Threshold = threshold
				rsaKeyShare.Entries = []RSAKeyShareEntry{}
			}
			rsaKeyShare.Entries = append(rsaKeyShare.Entries, keyShare)
			rsaKeyShares[playerIndex] = rsaKeyShare
		}
		i.Add(i, big.NewInt(1))
	}

	return rsaKeyShares, nil
}

func RSARecoverSecret(keyShares map[int]RSAKeyShare) (*rsa.PrivateKey, error) {
	if len(keyShares) <= 1 {
		return nil, fmt.Errorf("not enough shares")
	}

	players := make([]int, 0, len(keyShares))
	var threshold int
	for i, keyShare := range keyShares {
		if keyShare.Sharing != ADN06Sharing {
			return nil, fmt.Errorf("unsupported sharing type: %s", keyShare.Sharing.String())
		}
		players = append(players, i)
		var err error
		if threshold, err = setOrMatchInt(threshold, keyShare.Threshold, "threshold"); err != nil {
			return nil, err
		}
	}
	if threshold <= 0 {
		return nil, fmt.Errorf("invalid threshold in key shares: %d", threshold)
	}
	if len(players) <= threshold {
		return nil, fmt.Errorf("not enough players for threshold %d", threshold)
	}
	playerSubset := make([]int, threshold+1)
	copy(playerSubset, players)
	sort.Ints(playerSubset)

	dSum := big.NewInt(0)
	var d, e, n *big.Int

	for _, i := range playerSubset {
		keyShare, playerExist := keyShares[i]
		if !playerExist {
			return nil, fmt.Errorf("player %d does not have a key share", i)
		}
		keyShareFound := false
		for _, keyShareEntry := range keyShare.Entries {
			if intArraysEqual(playerSubset, keyShareEntry.Players) {
				var err error
				if d, err = setOrMatchBigInt(d, keyShareEntry.DPublic, "dPublic"); err != nil {
					return nil, err
				}
				if n, err = setOrMatchBigInt(n, keyShare.N, "N"); err != nil {
					return nil, err
				}
				if e, err = setOrMatchBigInt(e, keyShare.E, "E"); err != nil {
					return nil, err
				}
				dSum.Add(dSum, keyShareEntry.Di)
				keyShareFound = true
				break
			}
		}
		if !keyShareFound {
			return nil, fmt.Errorf("player %d does not have a key share for players %v", i, playerSubset)
		}
	}
	if d == nil {
		return nil, fmt.Errorf("d is nil")
	}
	if e == nil {
		return nil, fmt.Errorf("e is nil")
	}
	d.Add(d, dSum)

	p, q := recoverPQ(d, e, n)
	privateKey := rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: n,
			E: int(e.Int64()),
		},
		D:      d,
		Primes: []*big.Int{p, q},
	}
	privateKey.Precompute()

	return &privateKey, nil
}

func rsaSecretShare(players []int, privateKey *rsa.PrivateKey, limit1, limit2 *big.Int) []RSAKeyShareEntry {
	playerCount := len(players)
	keyShares := make([]RSAKeyShareEntry, playerCount)
	dPublic := new(big.Int).Set(privateKey.D)

	for i := 0; i < playerCount; i++ {
		di := random.BigInt(limit2)
		di.Sub(di, limit1)
		dPublic.Sub(dPublic, di)
		keyShares[i] = RSAKeyShareEntry{
			Players: players,
			Di:      di,
			DPublic: dPublic,
		}
	}
	return keyShares
}

func diLimits(playerCount int, privateKey *rsa.PrivateKey) (*big.Int, *big.Int) {
	const statisticalSecurityParameter = 128

	// Let n be the number of players. ADN06 blinds the private key with a value in the range [-n*N^2:n*N^2].
	limit1 := big.NewInt(int64(playerCount))
	limit1.Mul(limit1, big.NewInt(statisticalSecurityParameter))
	limit1.Mul(limit1, privateKey.N)
	limit2 := new(big.Int).Mul(big.NewInt(2), limit1)
	return limit1, limit2
}

func recoverPQ(d, e, n *big.Int) (*big.Int, *big.Int) {
	minusOne := new(big.Int).Mod(big.NewInt(-1), n)
	one := big.NewInt(1)
	two := big.NewInt(2)

	f := new(big.Int).Mul(e, d)
	f.Sub(f, one)

	g := new(big.Int).Set(f)
	for g.Bit(0) == 0 {
		g.Rsh(g, 1)
	}

	var a, b, c *big.Int
MainLoop:
	for {
		a = random.BigInt(n)
		b = new(big.Int).Exp(a, g, n)
		if b.Cmp(one) == 0 || b.Cmp(minusOne) == 0 {
			continue
		}
		for {
			c = new(big.Int).Exp(b, two, n)
			if c.Cmp(one) == 0 {
				break MainLoop
			}
			if c.Cmp(minusOne) == 0 {
				continue MainLoop
			}
			b.Set(c)
		}
	}

	p := new(big.Int).Sub(b, one)
	p.GCD(nil, nil, n, p)

	q := new(big.Int).Add(b, one)
	q.GCD(nil, nil, n, q)

	return p, q
}

func intArraysEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func setOrMatchInt(previousValue, newValue int, name string) (int, error) {
	if previousValue == 0 {
		return newValue, nil
	}
	if previousValue != newValue {
		return 0, fmt.Errorf("disagreement on %s", name)
	}
	return previousValue, nil
}

func setOrMatchBigInt(previousValue, newValue *big.Int, name string) (*big.Int, error) {
	if previousValue == nil {
		return new(big.Int).Set(newValue), nil
	}
	if previousValue.Cmp(newValue) != 0 {
		return nil, fmt.Errorf("disagreement on %s", name)
	}
	return previousValue, nil
}
