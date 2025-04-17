package ers

import (
	"fmt"
	"math/big"
	"sync"
)

var (
	binomialCache = &binomialMap{}
)

// Count returns "n choose k" that is the number of ways to choose a subset of k elements from a set of n elements
func numberOfCombinations(n, k int) *big.Int {
	v := new(big.Int)
	binomialCache.Get(v, n, k)
	return v
}

// Combination maps a number to one of the "n choose k" possible combinations. If the number larger than the number of
// combinations it is reduced modulo the number of combinations first. The returned combination will always have the lowest
// number first.
func combination(n, k int, combinationNumber *big.Int) []int {
	nChooseK := numberOfCombinations(n, k)
	combinationNumber = new(big.Int).Mod(combinationNumber, nChooseK)

	res := make([]int, k)
	c := new(big.Int).Set(big.NewInt(0))
	for i := k; i > 0; i-- {
		combinationNumber.Sub(combinationNumber, c)
		for j := n - 1; j >= 0; j-- {
			binomialCache.Get(c, j, i)
			if c.Cmp(combinationNumber) <= 0 {
				res[i-1] = j
				break
			}
		}
	}

	return res
}

// Implements a cache for binomial coefficients
type binomialMap struct {
	data map[string]*big.Int
	mu   sync.Mutex
}

func (m *binomialMap) Get(v *big.Int, n, k int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.data == nil {
		m.data = make(map[string]*big.Int)
	}
	key := fmt.Sprintf("%d-%d", n, k)

	value, ok := m.data[key]
	if !ok {
		value = new(big.Int).Binomial(int64(n), int64(k))
		m.data[key] = value
	}

	v.Set(value)
}
