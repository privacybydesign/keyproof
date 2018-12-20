package primeproofs

import "testing"
import "encoding/json"
import "github.com/mhe/gabi/big"

func TestAdditionProofFlow(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for Addition proof testing")
		return
	}

	const a = 4
	const b = 3
	const d = 2
	const n = 5

	a1 := newPedersonSecret(g, "a1", big.NewInt(a))
	a2 := newPedersonSecret(g, "a2", big.NewInt(b))
	mod := newPedersonSecret(g, "mod", big.NewInt(n))
	result := newPedersonSecret(g, "result", big.NewInt(d))

	bases := newBaseMerge(&g, &a1, &a2, &mod, &result)
	secrets := newSecretMerge(&a1, &a2, &mod, &result)

	s := newAdditionProofStructure("a1", "a2", "mod", "result", 3)
	if !s.IsTrue(&secrets) {
		t.Error("Incorrectly assessed proof setup as incorrect.")
	}

	listSecrets, commit := s.GenerateCommitmentsFromSecrets(g, []*big.Int{}, &bases, &secrets)

	proof := s.BuildProof(g, big.NewInt(12345), commit, &secrets)
	a1proof := a1.BuildProof(g, big.NewInt(12345))
	a1proof.SetName("a1")
	a2proof := a2.BuildProof(g, big.NewInt(12345))
	a2proof.SetName("a2")
	modproof := mod.BuildProof(g, big.NewInt(12345))
	modproof.SetName("mod")
	resultproof := result.BuildProof(g, big.NewInt(12345))
	resultproof.SetName("result")

	basesProof := newBaseMerge(&g, &a1proof, &a2proof, &modproof, &resultproof)
	proofdata := newProofMerge(&a1proof, &a2proof, &modproof, &resultproof)

	if !s.VerifyProofStructure(proof) {
		t.Error("Proof structure marked as invalid.\n")
		return
	}

	listProof := s.GenerateCommitmentsFromProof(g, []*big.Int{}, big.NewInt(12345), &basesProof, &proofdata, proof)

	if !listCmp(listSecrets, listProof) {
		t.Error("Commitment lists differ.\n")
	}
}

func TestAdditionProofVerifyStructure(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for Multiplication proof testing")
		return
	}

	var proof AdditionProof
	proof.ModAddResult = big.NewInt(1)
	proof.HiderResult = big.NewInt(1)

	s := newAdditionProofStructure("a1", "a2", "mod", "result", 3)
	if s.VerifyProofStructure(proof) {
		t.Error("Accepting missing rangeproof.\n")
	}

	proof.RangeProof = s.addRange.FakeProof(g)
	proof.ModAddResult = nil
	if s.VerifyProofStructure(proof) {
		t.Error("Accepting missing modaddresult.\n")
	}

	proof.ModAddResult = proof.HiderResult
	proof.HiderResult = nil
	if s.VerifyProofStructure(proof) {
		t.Error("Accepting missing hiderresult.\n")
	}
}

func TestAdditionProofFake(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for Multiplication proof testing")
		return
	}

	s := newAdditionProofStructure("a1", "a2", "mod", "result", 3)

	proof := s.FakeProof(g)

	if !s.VerifyProofStructure(proof) {
		t.Error("Rejecting fake proof structure.\n")
	}
}

func TestAdditionProofJSON(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for Multiplication proof testing")
		return
	}

	s := newAdditionProofStructure("a1", "a2", "mod", "result", 3)

	proofBefore := s.FakeProof(g)

	proofJSON, err := json.Marshal(proofBefore)
	if err != nil {
		t.Errorf("error during json marshal: %s", err.Error())
		return
	}

	var proofAfter AdditionProof
	err = json.Unmarshal(proofJSON, &proofAfter)
	if err != nil {
		t.Errorf("error during json unmarshal: %s", err.Error())
		return
	}

	if !s.VerifyProofStructure(proofAfter) {
		t.Error("json'ed proof structure invalid")
	}
}
