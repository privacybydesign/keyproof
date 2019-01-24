package common

import (
	"encoding/hex"
	"testing"

	"github.com/privacybydesign/gabi/big"
)

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

func TestCPRNG(t *testing.T) {
	var seed [32]byte
	expected := "f29000b62a499fd0a9f39a6add2e7780c7b519846a11411cd6ac07cb03f801a84ef4b88bebd54953c37ffaf66efaca7b80c3017e8f89ab315ede32b11e48ab50d5786900334bbaad31a868ca3c29221b99ebccc0117949cd663c44c06a1c58b05daad7132f80983dae88ecf9ce714a1b600411a4cb4d0da02e107f8d0bcfdab864009471a3394f76374e38bfdc9fe26c62ac2e4b9ec5049108dccdb6488f325cf3297d5a71a5d1734dd46661023ea39f7402facdf1802b42d88a715615324bd502bddc6de19403882a27cdf934adffc9483c475aeb20edf61bfa6a18777a7ada695ebda390508948b1fc69971a26a169c0de48d769b197cd5cf9bb5f798f49d0"
	for i := 0; i < 32; i++ {
		seed[i] = byte(i)
	}
	var buf [256]byte
	rng, err := NewCPRNG(&seed)
	if err != nil {
		t.Fatalf("NewCPRNG: %v", err)
	}
	for i := 0; i < 256; i++ {
		rng, _ = NewCPRNG(&seed)
		rng.Read(buf[0:i])
		if hex.EncodeToString(buf[:i]) != expected[:2*i] {
			t.Fatalf("TestCPRNG (1): %d", i)
		}
	}
	rng, _ = NewCPRNG(&seed)
	for i := 0; i < 16; i++ {
		rng.Read(buf[i*16 : (i+1)*16])
	}
	if hex.EncodeToString(buf[:]) != expected[:] {
		t.Fatalf("TestCPRNG (2)")
	}
	rng, _ = NewCPRNG(&seed)
	for i := 0; i < 8; i++ {
		rng.Read(buf[i*32 : (i+1)*32])
	}
	if hex.EncodeToString(buf[:]) != expected[:] {
		t.Fatalf("TestCPRNG (3)")
	}
	for j := 1; j < 16; j++ {
		rng, _ = NewCPRNG(&seed)
		for i := 0; i < 8; i++ {
			rng.Read(buf[:j])
			if hex.EncodeToString(buf[:j]) != expected[32*i:32*i+2*j] {
				t.Fatalf("TestCPRNG (4)")
			}
		}
	}
	for j := 17; j < 31; j++ {
		rng, _ = NewCPRNG(&seed)
		for i := 0; i < 8; i++ {
			rng.Read(buf[:j])
			if hex.EncodeToString(buf[:j]) != expected[64*i:64*i+2*j] {
				t.Fatalf("TestCPRNG (5)")
			}
		}
	}
}
