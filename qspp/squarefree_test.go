package qspp

import "testing"
import "github.com/mhe/gabi/big"

func TestSquareFreeCycle(t *testing.T) {
	const p = 1031
	const q = 1063
	proof := SquareFreeBuildProof(big.NewInt(int64(p*q)), big.NewInt(int64((p-1)*(q-1))), big.NewInt(12345), big.NewInt(0))
	if !SquareFreeVerifyStructure(proof) {
		t.Error("proof structure rejected")
	}
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

func TestSquareFreeVerifyStructure(t *testing.T) {
	const p = 1031
	const q = 1063
	proof := SquareFreeBuildProof(big.NewInt(int64(p*q)), big.NewInt(int64((p-1)*(q-1))), big.NewInt(12345), big.NewInt(0))

	listBackup := proof.Responses
	proof.Responses = proof.Responses[:len(proof.Responses)-1]
	if SquareFreeVerifyStructure(proof) {
		t.Error("Accepting too short responses")
	}
	proof.Responses = listBackup

	valBackup := proof.Responses[2]
	proof.Responses[2] = nil
	if SquareFreeVerifyStructure(proof) {
		t.Error("Accepting missing respone")
	}
	proof.Responses[2] = valBackup

	if !SquareFreeVerifyStructure(proof) {
		t.Error("testcase corrupted testdata")
	}
}
