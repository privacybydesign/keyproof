package primeproofs

import "testing"
import "github.com/mhe/gabi/big"

func TestSafePrimeProof(t *testing.T) {
	g, _ := buildGroup(big.NewInt(227))
	const p = 47
	const q = 23

	s := newSafePrimeProofStructure(big.NewInt(p * q))
	proof := s.buildProof(g, big.NewInt((p-1)/2), big.NewInt((q-1)/2))

	ok := s.verifyProof(g, proof)
	if !ok {
		t.Error("Proof rejected.\n")
	}
}
