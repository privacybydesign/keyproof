package primeproofs

import (
	"github.com/privacybydesign/gabi/big"

	"github.com/privacybydesign/keyproof/common"

	"github.com/bwesterb/go-exptable"
)

type group struct {
	P     *big.Int
	order *big.Int
	g     *big.Int
	h     *big.Int

	gTable exptable.Table
	hTable exptable.Table

	PMod     common.FastMod
	orderMod common.FastMod
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

	result.gTable.Compute(result.g.Value(), result.P.Value(), 7)
	result.hTable.Compute(result.h.Value(), result.P.Value(), 7)

	result.PMod.Set(result.P)
	result.orderMod.Set(result.order)

	return result, true
}
