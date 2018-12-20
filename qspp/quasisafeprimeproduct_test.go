package qspp

import "testing"
import "encoding/json"
import "github.com/privacybydesign/keyproof/common"
import "github.com/mhe/gabi/big"

func TestQuasiSafePrimeProductCycle(t *testing.T) {
	const p = 13451
	const q = 13901
	listBefore, commit := QuasiSafePrimeProductBuildCommitments([]*big.Int{}, big.NewInt(p), big.NewInt(q))
	proof := QuasiSafePrimeProductBuildProof(big.NewInt(p), big.NewInt(q), big.NewInt(12345), commit)
	if !QuasiSafePrimeProductVerifyStructure(proof) {
		t.Error("Proof structure rejected")
	}
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
	challengeBefore := common.HashCommit(listBefore)
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
	challengeAfter := common.HashCommit(listAfter)
	ok := QuasiSafePrimeProductVerifyProof(big.NewInt((2*p+1)*(2*q+1)), challengeAfter, proofAfter)
	if !ok {
		t.Error("JSON proof rejected")
	}
}

func TestQuasiSafePrimeProductVerifyStructure(t *testing.T) {
	const p = 13451
	const q = 13901
	_, commit := QuasiSafePrimeProductBuildCommitments([]*big.Int{}, big.NewInt(p), big.NewInt(q))
	proof := QuasiSafePrimeProductBuildProof(big.NewInt(p), big.NewInt(q), big.NewInt(12345), commit)
	
	valBackup := proof.SFproof.Responses[2]
	proof.SFproof.Responses[2] = nil
	if QuasiSafePrimeProductVerifyStructure(proof) {
		t.Error("Accepting corrupted sfproof")
	}
	proof.SFproof.Responses[2] = valBackup
	
	valBackup = proof.PPPproof.Responses[2]
	proof.PPPproof.Responses[2] = nil
	if QuasiSafePrimeProductVerifyStructure(proof) {
		t.Error("Accepting corrupted pppproof")
	}
	proof.PPPproof.Responses[2] = valBackup
	
	valBackup = proof.DPPproof.Responses[2]
	proof.DPPproof.Responses[2] = nil
	if QuasiSafePrimeProductVerifyStructure(proof) {
		t.Error("Accepting corrupted dppproof")
	}
	proof.DPPproof.Responses[2] = valBackup
	
	valBackup = proof.ASPPproof.Responses[2]
	proof.ASPPproof.Responses[2] = nil
	if QuasiSafePrimeProductVerifyStructure(proof) {
		t.Error("Accepting corrupted asppproof")
	}
	proof.ASPPproof.Responses[2] = valBackup
	
	if !QuasiSafePrimeProductVerifyStructure(proof) {
		t.Error("testcase corrupted testdata")
	}
}
