package qspp

import "testing"
import "encoding/json"
import "github.com/mhe/gabi/big"

func TestQuasiSafePrimeProductCycle(t *testing.T) {
	const p = 13451
	const q = 13901
	listBefore, commit := QuasiSafePrimeProductBuildCommitments([]*big.Int{}, big.NewInt(p), big.NewInt(q))
	proof := QuasiSafePrimeProductBuildProof(big.NewInt(p), big.NewInt(q), big.NewInt(12345), commit)
	listAfter := QuasiSafePrimeProductExtractCommitments([]*big.Int{}, proof)
	ok := QuasiSafePrimeProductVerifyProof(big.NewInt((2*p+1)*(2*q+1)), big.NewInt(12345), proof)
	if !ok {
		t.Error("QuasiSafePrimeProduct rejected")
	}
	if len(listBefore) != len(listAfter) {
		t.Error("Difference between commitment contribution lengths")
	}
	for i, ref := range listBefore {
		if ref.Cmp(listAfter[i]) != 0 {
			t.Errorf("Difference between commitment %v\n", i)
		}
	}
}

func TestQuasiSafePrimeProductFullCycle(t *testing.T) {
	// Build proof
	const p = 13451
	const q = 13901
	listBefore, commit := QuasiSafePrimeProductBuildCommitments([]*big.Int{}, big.NewInt(p), big.NewInt(q))
	challengeBefore := hashCommit(listBefore)
	proofBefore := QuasiSafePrimeProductBuildProof(big.NewInt(p), big.NewInt(q), challengeBefore, commit)
	proofJSON, err := json.Marshal(proofBefore)
	if err != nil {
		t.Error(err.Error())
		return
	}

	// Validate proof json
	var proofAfter QuasiSafePrimeProductProof
	err = json.Unmarshal(proofJSON, &proofAfter)
	if err != nil {
		t.Error(err.Error())
		return
	}
	listAfter := QuasiSafePrimeProductExtractCommitments([]*big.Int{}, proofAfter)
	challengeAfter := hashCommit(listAfter)
	ok := QuasiSafePrimeProductVerifyProof(big.NewInt((2*p+1)*(2*q+1)), challengeAfter, proofAfter)
	if !ok {
		t.Error("JSON proof rejected")
	}
}
