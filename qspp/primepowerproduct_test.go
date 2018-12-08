package qspp

import "testing"
import "github.com/mhe/gabi/big"

func TestPrimePowerProductCycle(t *testing.T) {
	const p = 1031
	const q = 1061
	proof := PrimePowerProductBuildProof(big.NewInt(int64(p)), big.NewInt(int64(q)), big.NewInt(12345), big.NewInt(1))
	ok := PrimePowerProductVerifyProof(big.NewInt(int64(p*q)), big.NewInt(12345), big.NewInt(1), proof)
	if !ok {
		t.Error("PrimePowerProductProof rejected")
	}
}

func TestPrimePowerProductCycleIncorrect(t *testing.T) {
	const p = 1031
	const q = 1061
	proof := PrimePowerProductBuildProof(big.NewInt(int64(p)), big.NewInt(int64(q)), big.NewInt(12345), big.NewInt(1))
	proof.Responses[0].Add(proof.Responses[0], big.NewInt(1))
	ok := PrimePowerProductVerifyProof(big.NewInt(int64(p*q)), big.NewInt(12345), big.NewInt(1), proof)
	if ok {
		t.Error("Incorrect PrimePowerProductProof accepted")
	}
}

func TestPrimePowerProductCycleWrongChallenge(t *testing.T) {
	const p = 1031
	const q = 1061
	proof := PrimePowerProductBuildProof(big.NewInt(int64(p)), big.NewInt(int64(q)), big.NewInt(12345), big.NewInt(1))
	ok := PrimePowerProductVerifyProof(big.NewInt(int64(p*q)), big.NewInt(12346), big.NewInt(1), proof)
	if ok {
		t.Error("Incorrect PrimePowerProductProof accepted")
	}
}

func TestPrimePowerProductCycleWrongIndex(t *testing.T) {
	const p = 1031
	const q = 1061
	proof := PrimePowerProductBuildProof(big.NewInt(int64(p)), big.NewInt(int64(q)), big.NewInt(12345), big.NewInt(1))
	ok := PrimePowerProductVerifyProof(big.NewInt(int64(p*q)), big.NewInt(12345), big.NewInt(2), proof)
	if ok {
		t.Error("Incorrect PrimePowerProductProof accepted")
	}
}

func TestPrimePowerProductCycleTooShort(t *testing.T) {
	const p = 1031
	const q = 1061
	proof := PrimePowerProductBuildProof(big.NewInt(int64(p)), big.NewInt(int64(q)), big.NewInt(12345), big.NewInt(1))
	proof.Responses = proof.Responses[:len(proof.Responses)-1]
	ok := PrimePowerProductVerifyProof(big.NewInt(int64(p*q)), big.NewInt(12345), big.NewInt(1), proof)
	if ok {
		t.Error("Incorrect PrimePowerProductProof accepted")
	}
}

func TestPrimePowerProductEmpty(t *testing.T) {
	const p = 1031
	const q = 1061
	var proof PrimePowerProductProof
	proof.Responses = []*big.Int{}
	ok := PrimePowerProductVerifyProof(big.NewInt(int64(p*q)), big.NewInt(12345), big.NewInt(1), proof)
	if ok {
		t.Error("Incorrect PrimePowerProductProof accepted")
	}
}
