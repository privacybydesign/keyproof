package common

import "testing"
import "github.com/privacybydesign/gabi/big"

func TestLegendre(t *testing.T) {
	primes := []*big.Int{
		big.NewInt(3),
		big.NewInt(5),
		big.NewInt(7),
		big.NewInt(11),
		big.NewInt(13),
		big.NewInt(17),
	}

	for _, prime := range primes {
		for i := 0; i < int(prime.Int64()); i++ {
			ref := new(big.Int).Exp(big.NewInt(int64(i)), new(big.Int).Rsh(prime, 1), prime)
			rv := ref.Int64()
			if rv > 1 {
				rv -= prime.Int64()
			}
			if rv != int64(LegendreSymbol(big.NewInt(int64(i)), prime)) {
				t.Errorf("Incorrect result %v for input (%v, %v) (ref: %v)", LegendreSymbol(big.NewInt(int64(i)), prime), i, prime, ref)
			}
		}
	}
}

func TestCrt20(t *testing.T) {
	for i := 0; i < 20; i++ {
		if Crt(big.NewInt(int64(i%4)), big.NewInt(4), big.NewInt(int64(i%5)), big.NewInt(5)).Cmp(big.NewInt(int64(i))) != 0 {
			t.Errorf("Incorrect reconstruction %d of %d.", Crt(big.NewInt(int64(i%4)), big.NewInt(4), big.NewInt(int64(i%5)), big.NewInt(5)).Int64(), i)
		}
	}
}

func TestCrt35(t *testing.T) {
	for i := 0; i < 35; i++ {
		if Crt(big.NewInt(int64(i%5)), big.NewInt(5), big.NewInt(int64(i%7)), big.NewInt(7)).Cmp(big.NewInt(int64(i))) != 0 {
			t.Errorf("Incorrect reconstruction %d of %d.", Crt(big.NewInt(int64(i%5)), big.NewInt(5), big.NewInt(int64(i%7)), big.NewInt(7)).Int64(), i)
		}
	}
}

func TestCrtError(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("CRT Failed to detect gcd(pa, pb) != 1")
		}
	}()
	Crt(big.NewInt(1), big.NewInt(5), big.NewInt(1), big.NewInt(35))
}

func TestPrimeSqrt7(t *testing.T) {
	for i := 0; i < 7; i++ {
		res, ok := PrimeSqrt(new(big.Int).Mod(big.NewInt(int64(i*i)), big.NewInt(7)), big.NewInt(7))
		if !ok {
			t.Errorf("Incorrect rejection of %d as non-square.", (i*i)%7)
		} else {
			if res.Cmp(big.NewInt(int64(i))) != 0 && res.Cmp(big.NewInt(int64(7-i))) != 0 {
				t.Errorf("Incorrect root %d of %d.", res.Int64(), i)
			}
		}
	}
}

func TestPrimeSqrt13(t *testing.T) {
	for i := 0; i < 13; i++ {
		res, ok := PrimeSqrt(big.NewInt(int64((i*i)%13)), big.NewInt(13))
		if !ok {
			t.Errorf("Incorrect rejection of %d as non-square.", (i*i)%13)
		} else {
			if res.Cmp(big.NewInt(int64(i))) != 0 && res.Cmp(big.NewInt(int64(13-i))) != 0 {
				t.Errorf("Incorrect root %d of %d", res.Int64(), (i*i)%13)
			}
		}
	}
}

func TestPrimeSqrt17(t *testing.T) {
	for i := 0; i < 17; i++ {
		res, ok := PrimeSqrt(big.NewInt(int64((i*i)%17)), big.NewInt(17))
		if !ok {
			t.Errorf("Incorrect rejection of %d as non-square.", (i*i)%17)
		} else {
			if res.Cmp(big.NewInt(int64(i))) != 0 && res.Cmp(big.NewInt(int64(17-i))) != 0 {
				t.Errorf("Incorrect root %d of %d", res.Int64(), (i*i)%17)
			}
		}
	}
}

func TestPrimeSqrtNonRoot(t *testing.T) {
	table := []struct {
		a  *big.Int
		pa *big.Int
	}{
		{big.NewInt(3), big.NewInt(7)},
		{big.NewInt(5), big.NewInt(7)},
		{big.NewInt(6), big.NewInt(7)},
		{big.NewInt(2), big.NewInt(13)},
		{big.NewInt(5), big.NewInt(13)},
		{big.NewInt(6), big.NewInt(13)},
		{big.NewInt(7), big.NewInt(13)},
		{big.NewInt(8), big.NewInt(13)},
		{big.NewInt(11), big.NewInt(13)},
	}

	for _, row := range table {
		_, ok := PrimeSqrt(row.a, row.pa)
		if ok {
			t.Errorf("Incorrect acceptence of %d as square mod %d", row.a.Int64(), row.pa.Int64())
		}
	}
}

func TestModSqrt20(t *testing.T) {
	factors := []*big.Int{
		big.NewInt(4),
		big.NewInt(5),
	}

	for i := 0; i < 20; i++ {
		res, ok := ModSqrt(big.NewInt(int64((i*i)%20)), factors)
		if !ok {
			t.Errorf("Incorrect rejection of %d as non-square. (root %d)", (i*i)%20, i)
		} else {
			sqr := new(big.Int).Mod(new(big.Int).Mul(res, res), big.NewInt(20))
			if sqr.Int64() != int64((i*i)%20) {
				t.Errorf("Incorrect root %d of %d.", res.Int64(), (i*i)%20)
			}
		}
	}
}

func TestModSqrt140(t *testing.T) {
	factors := []*big.Int{
		big.NewInt(4),
		big.NewInt(5),
		big.NewInt(7),
	}

	for i := 0; i < 140; i++ {
		res, ok := ModSqrt(big.NewInt(int64((i*i)%140)), factors)
		if !ok {
			t.Errorf("Incorrect rejection fo %d as non-square. (root %d)", (i*i)%140, i)
		} else {
			sqr := new(big.Int).Mod(new(big.Int).Mul(res, res), big.NewInt(140))
			if sqr.Int64() != int64((i*i)%140) {
				t.Errorf("Incorrect root %v of %v.", res.Int64(), (i*i)%140)
			}
		}
	}
}

func TestModSqrtNonRoot(t *testing.T) {
	values := []*big.Int{
		big.NewInt(2),
		big.NewInt(3),
		big.NewInt(6),
		big.NewInt(7),
		big.NewInt(8),
		big.NewInt(10),
		big.NewInt(11),
		big.NewInt(12),
		big.NewInt(13),
		big.NewInt(14),
		big.NewInt(15),
		big.NewInt(17),
		big.NewInt(18),
		big.NewInt(19),
	}

	factors := []*big.Int{
		big.NewInt(4),
		big.NewInt(5),
	}

	for _, val := range values {
		_, ok := ModSqrt(val, factors)
		if ok {
			t.Errorf("Incorrect acceptence of %v as square mod 20", val)
		}
	}
}
