package primeproofs

import "crypto/rand"
import "github.com/mhe/gabi/big"

// Generate a (cryptographically secure!) random number
func randomBigInt(limit *big.Int) *big.Int {
	res, err := big.RandInt(rand.Reader, limit)
	if err != nil {
		panic(err.Error())
	}
	return res
}
