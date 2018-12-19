package primeproofs

import "github.com/mhe/gabi/big"

type group struct {
	P     *big.Int
	order *big.Int
	g     *big.Int
	h     *big.Int
}

func buildGroup(prime *big.Int) (group, bool) {
	var result group

	if !prime.ProbablyPrime(80) {
		return result, false
	}

	result.P = new(big.Int).Set(prime)
	result.order = new(big.Int).Rsh(prime, 1)

	if !result.order.ProbablyPrime(80) {
		return result, false
	}

	result.g = new(big.Int).Exp(big.NewInt(0x41424344), big.NewInt(0x45464748), result.P)
	result.h = new(big.Int).Exp(big.NewInt(0x494A4B4C), big.NewInt(0x4D4E4F50), result.P)

	return result, true
}
