package primeproofs

import "crypto/sha256"
import "encoding/asn1"
import "github.com/mhe/gabi/big"
import gobig "math/big"

func hashCommit(values []*big.Int) *big.Int {
	// The first element is the number of elements
	var tmp []interface{}
	offset := 0
	tmp = make([]interface{}, len(values)+1)
	tmp[offset] = gobig.NewInt(int64(len(values)))
	offset++
	for i, v := range values {
		tmp[i+offset] = v.Value()
	}
	r, _ := asn1.Marshal(tmp)

	h := sha256.New()
	_, _ = h.Write(r)
	return new(big.Int).SetBytes(h.Sum(nil))
}

func getHashNumber(a *big.Int, b *big.Int, index int, bitlen uint) *big.Int {
	tmp := []*big.Int{}
	if a != nil {
		tmp = append(tmp, a)
	}
	if b != nil {
		tmp = append(tmp, b)
	}
	tmp = append(tmp, big.NewInt(int64(index)))
	countIdx := len(tmp)
	tmp = append(tmp, big.NewInt(0))

	k := uint(0)
	res := big.NewInt(0)
	for k < bitlen {
		cur := hashCommit(tmp)
		cur.Lsh(cur, uint(k))
		res.Add(res, cur)
		k += 256
		tmp[countIdx].Add(tmp[countIdx], big.NewInt(1))
	}

	return res
}
