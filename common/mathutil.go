package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync/atomic"

	"github.com/privacybydesign/gabi/big"
)

// Often we need to refer to the same small constant big numbers, no point in
// creating them again and again.
var (
	bigZERO  = big.NewInt(0)
	bigONE   = big.NewInt(1)
	bigTWO   = big.NewInt(2)
	bigTHREE = big.NewInt(3)
	bigFOUR  = big.NewInt(4)
	bigFIVE  = big.NewInt(5)
	bigEIGHT = big.NewInt(8)
)

// legendreSymbol calculates the Legendre symbol (a/p).
func LegendreSymbol(a, p *big.Int) int {
	// Adapted from: https://programmingpraxis.com/2012/05/01/legendres-symbol/
	// Probably needs more extensive checking? Also, no optimization has been applied.
	j := 1

	// Make a copy of the arguments
	// rule 5
	n := new(big.Int).Mod(a, p)
	m := new(big.Int).Set(p)

	tmp := new(big.Int)
	for n.Cmp(bigZERO) != 0 {
		// rules 3 and 4
		t := 0
		for n.Bit(0) == 0 {
			n.Rsh(n, 1)
			t++
		}
		tmp.Mod(m, bigEIGHT)
		if t&1 == 1 && (tmp.Cmp(bigTHREE) == 0 || tmp.Cmp(bigFIVE) == 0) {
			j = -j
		}

		// rule 6
		if tmp.Mod(m, bigFOUR).Cmp(bigTHREE) == 0 && tmp.Mod(n, bigFOUR).Cmp(bigTHREE) == 0 {
			j = -j
		}

		// rules 5 and 6
		m.Mod(m, n)
		n, m = m, n
	}
	if m.Cmp(bigONE) == 0 {
		return j
	}
	return 0
}

// Find a number x (mod pa*pb) such that x = a (mod pa) and x = b (mod pb)
func Crt(a *big.Int, pa *big.Int, b *big.Int, pb *big.Int) *big.Int {
	s1 := new(big.Int)
	s2 := new(big.Int)
	z := new(big.Int).GCD(s2, s1, pa, pb)
	if z.Cmp(bigONE) != 0 {
		panic("Incorrect input to CRT")
	}
	result := new(big.Int).Add(
		new(big.Int).Mul(new(big.Int).Mul(a, s1), pb),
		new(big.Int).Mul(new(big.Int).Mul(b, s2), pa))

	n := new(big.Int).Mul(pa, pb)
	result.Mod(result, n)
	return result
}

// Calculate sqrt modulo a prime
func PrimeSqrt(a *big.Int, pa *big.Int) (*big.Int, bool) {
	// Handle the case a == 0
	if a.Cmp(bigZERO) == 0 {
		return big.NewInt(0), true // should be a new big int!
	}

	// Check number is a square
	validation := new(big.Int).Exp(a, new(big.Int).Rsh(pa, 1), pa)
	if validation.Cmp(bigONE) != 0 {
		return nil, false
	}

	// Shortcut when pa = 3 (mod 4)
	rem := new(big.Int).Mod(pa, bigFOUR)
	if rem.Cmp(bigTHREE) == 0 {
		result := new(big.Int).Exp(a, new(big.Int).Add(new(big.Int).Rsh(pa, 2), big.NewInt(1)), pa)
		return result, true
	}

	// Find a non-residue
	z := big.NewInt(2) // Should be a new big int!
	for LegendreSymbol(new(big.Int).Set(z), new(big.Int).Set(pa)) != -1 {
		z.Add(z, bigONE)
	}

	// Split pa-1 as 2^S*Q
	Q := new(big.Int).Sub(pa, big.NewInt(1))
	M := 0
	for Q.Bit(0) == 0 {
		Q.Rsh(Q, 1)
		M++
	}

	// Setup for main loop
	c := new(big.Int).Exp(z, Q, pa)
	t := new(big.Int).Exp(a, Q, pa)
	R := new(big.Int).Exp(a, new(big.Int).Add(new(big.Int).Rsh(Q, 1), big.NewInt(1)), pa)

	// Main loop
	for t.Cmp(bigONE) != 0 {
		tp := new(big.Int).Set(t)
		i := 0
		for tp.Cmp(bigONE) != 0 {
			tp.Exp(tp, big.NewInt(2), pa)
			i++
		}
		b := new(big.Int).Exp(c, new(big.Int).Lsh(bigONE, uint(M-i-1)), pa)
		M = i
		c.Exp(b, bigTWO, pa)
		t.Mod(new(big.Int).Mul(t, c), pa)
		R.Mod(new(big.Int).Mul(R, b), pa)
	}

	return R, true
}

// Calculate Sqrt modulo a number with given prime factors. Also allows 4 as a factor
// All factors should be relatively prime to each other!
func ModSqrt(a *big.Int, factors []*big.Int) (*big.Int, bool) {
	n := big.NewInt(1) // Should be new big int!
	res := new(big.Int)

	// Solve problem one factor at a time
	for i, fac := range factors {
		var locRes *big.Int
		if fac.Cmp(bigFOUR) == 0 {
			// Special case for 4
			if a.Bit(1) != 0 {
				return nil, false
			}
			if a.Bit(0) == 0 {
				locRes = big.NewInt(2) // For safety sake, keep new
			} else {
				locRes = big.NewInt(1) // For safety sake, keep new
			}
		} else {
			var ok bool
			locRes, ok = PrimeSqrt(new(big.Int).Mod(a, fac), fac)
			if !ok {
				return nil, false
			}
		}
		if i == 0 {
			res = locRes
		} else {
			res = Crt(res, n, locRes, fac)
		}
		n.Mul(n, fac)
	}
	return res, true
}

var globalCprng *CPRNG

// Simple threadsafe cryptographically secure pseudo-random number generator.
//
// Implemented with AES in counter mode with the seed as key and an
// atomic uint64 as counter.
type CPRNG struct {
	block   cipher.Block
	counter uint64
}

func NewCPRNG(seed *[32]byte) (*CPRNG, error) {
	cipher, err := aes.NewCipher(seed[:])
	if err != nil {
		return nil, err
	}
	return &CPRNG{
		block:   cipher,
		counter: 0,
	}, nil
}

func init() {
	var seed [32]byte
	_, err := rand.Reader.Read(seed[:])
	if err != nil {
		panic(fmt.Sprintf("Failed to generate seed for CPRNG: %v", err))
	}
	cprng, err := NewCPRNG(&seed)
	if err != nil {
		panic(fmt.Sprintf("Failed to initialize CPRNG: %v", err))
	}
	globalCprng = cprng
}

func (c *CPRNG) Read(buf []byte) (n int, err error) {
	var pt, ct [16]byte
	n = len(buf)
	if n == 0 {
		return
	}

	// Number of blocks required
	nBlocks := uint64(((len(buf) - 1) / 16) + 1)

	// Atomically increment counter by the number of blocks and set iv to
	// the first available block.
	iv := atomic.AddUint64(&c.counter, nBlocks) - nBlocks
	for {
		binary.LittleEndian.PutUint64(pt[:], iv)
		iv++

		// Still 16 bytes to go?  Then encrypt directly into buf.
		if len(buf) >= 16 {
			c.block.Encrypt(buf, pt[:])
			buf = buf[16:]
			continue
		}
		if len(buf) == 0 {
			break
		}

		// Otherwise, encrypt into ct and copy into buf.
		c.block.Encrypt(ct[:], pt[:])
		copy(buf, ct[:len(buf)])
		break
	}
	return
}

// Derives a random number uniformly chosen below the given limit
// from a random 256 bit seed generated when the application starts.
func RandomBigInt(limit *big.Int) *big.Int {
	res, err := big.RandInt(globalCprng, limit)
	if err != nil {
		panic(fmt.Sprintf("big.RandInt failed: %v", err))
	}
	return res
}
