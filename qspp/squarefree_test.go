package qspp

import "testing"
import "github.com/mhe/gabi/big"

func TestSquareFreeCycle(t *testing.T) {
	const p = 1031
	const q = 1063
	proof := SquareFreeBuildProof(big.NewInt(int64(p*q)), big.NewInt(int64((p-1)*(q-1))), big.NewInt(12345), big.NewInt(0))
	ok := SquareFreeVerifyProof(big.NewInt(int64(p*q)), big.NewInt(12345), big.NewInt(0), proof)
	if !ok {
		t.Errorf("SquareFreeProof rejected.")
	}
}

func TestSquareFreeCycleIncorrect(t *testing.T) {
	const p = 1031
	const q = 1063
	proof := SquareFreeBuildProof(big.NewInt(int64(p*q)), big.NewInt(int64((p-1)*(q-1))), big.NewInt(12345), big.NewInt(0))
	proof.Responses[0].Add(proof.Responses[0], big.NewInt(1))
	ok := SquareFreeVerifyProof(big.NewInt(int64(p*q)), big.NewInt(12345), big.NewInt(0), proof)
	if ok {
		t.Errorf("Incorrect SquareFreeProof accepted.")
	}
}

func TestSquareFreeCycleWrongChallenge(t *testing.T) {
	const p = 1031
	const q = 1063
	proof := SquareFreeBuildProof(big.NewInt(int64(p*q)), big.NewInt(int64((p-1)*(q-1))), big.NewInt(12345), big.NewInt(0))
	ok := SquareFreeVerifyProof(big.NewInt(int64(p*q)), big.NewInt(12346), big.NewInt(0), proof)
	if ok {
		t.Errorf("Incorrect SquareFreeProof accepted.")
	}
}

func TestSquareFreeCycleWrongIndex(t *testing.T) {
	const p = 1031
	const q = 1063
	proof := SquareFreeBuildProof(big.NewInt(int64(p*q)), big.NewInt(int64((p-1)*(q-1))), big.NewInt(12345), big.NewInt(0))
	ok := SquareFreeVerifyProof(big.NewInt(int64(p*q)), big.NewInt(12345), big.NewInt(1), proof)
	if ok {
		t.Errorf("Incorrect SquareFreeProof accepted.")
	}
}

func TestSquareFreeCycleTooShort(t *testing.T) {
	const p = 1031
	const q = 1063
	proof := SquareFreeBuildProof(big.NewInt(int64(p*q)), big.NewInt(int64((p-1)*(q-1))), big.NewInt(12345), big.NewInt(0))
	proof.Responses = proof.Responses[:len(proof.Responses)-1]
	ok := SquareFreeVerifyProof(big.NewInt(int64(p*q)), big.NewInt(12345), big.NewInt(0), proof)
	if ok {
		t.Errorf("Incorrect SquareFreeProof accepted.")
	}
}

func TestSquareFreeRejectEmpty(t *testing.T) {
	var proof SquareFreeProof
	proof.Responses = []*big.Int{}
	ok := SquareFreeVerifyProof(big.NewInt(1031), big.NewInt(12345), big.NewInt(0), proof)
	if ok {
		t.Errorf("Incorrect SquareFreeProof accepted.")
	}
}
