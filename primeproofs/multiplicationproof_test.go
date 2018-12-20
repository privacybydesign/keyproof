package primeproofs

import "testing"
import "encoding/json"
import "github.com/mhe/gabi/big"

func TestMultiplicationProofFlow(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for Multiplication proof testing")
		return
	}

	const a = 2
	const b = 3
	const d = 1
	const n = 5

	m1 := newPedersonSecret(g, "m1", big.NewInt(a))
	m2 := newPedersonSecret(g, "m2", big.NewInt(b))
	mod := newPedersonSecret(g, "mod", big.NewInt(n))
	result := newPedersonSecret(g, "result", big.NewInt(d))

	bases := newBaseMerge(&g, &m1, &m2, &mod, &result)
	secrets := newSecretMerge(&m1, &m2, &mod, &result)

	s := newMultiplicationProofStructure("m1", "m2", "mod", "result", 3)
	if !s.IsTrue(&secrets) {
		t.Error("Incorrectly assessed proof setup as incorrect.")
	}

	listSecrets, commit := s.GenerateCommitmentsFromSecrets(g, []*big.Int{}, &bases, &secrets)

	proof := s.BuildProof(g, big.NewInt(12345), commit, &secrets)
	m1proof := m1.BuildProof(g, big.NewInt(12345))
	m1proof.SetName("m1")
	m2proof := m2.BuildProof(g, big.NewInt(12345))
	m2proof.SetName("m2")
	modproof := mod.BuildProof(g, big.NewInt(12345))
	modproof.SetName("mod")
	resultproof := result.BuildProof(g, big.NewInt(12345))
	resultproof.SetName("result")

	basesProof := newBaseMerge(&g, &m1proof, &m2proof, &modproof, &resultproof)
	proofdata := newProofMerge(&m1proof, &m2proof, &modproof, &resultproof)

	if !s.VerifyProofStructure(proof) {
		t.Error("Proof structure marked as invalid.\n")
		return
	}

	listProof := s.GenerateCommitmentsFromProof(g, []*big.Int{}, big.NewInt(12345), &basesProof, &proofdata, proof)

	if !listCmp(listSecrets, listProof) {
		t.Error("Commitment lists differ.\n")
	}
}

func TestMultiplicationProofVerifyStructure(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for Multiplication proof testing")
		return
	}

	var proof MultiplicationProof
	s := newMultiplicationProofStructure("m1", "m2", "mod", "result", 3)

	proof.ModMultResult = big.NewInt(1)
	proof.HiderResult = big.NewInt(1)
	if s.VerifyProofStructure(proof) {
		t.Error("Accepting malformed range proof")
	}

	proof.RangeProof = s.multRange.FakeProof(g)
	proof.ModMultResult = nil
	if s.VerifyProofStructure(proof) {
		t.Error("Accepting missing modmulresult")
	}

	proof.ModMultResult = proof.HiderResult
	proof.HiderResult = nil
	if s.VerifyProofStructure(proof) {
		t.Error("Accepting missing hiderresult")
	}
}

func TestMultiplicationProofFake(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for Multiplication proof testing")
		return
	}

	s := newMultiplicationProofStructure("m1", "m2", "mod", "result", 3)

	proof := s.FakeProof(g)

	if !s.VerifyProofStructure(proof) {
		t.Error("Fake proof structure rejected.")
	}
}

func TestMultiplicationProofJSON(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for Multiplication proof testing")
		return
	}

	s := newMultiplicationProofStructure("m1", "m2", "mod", "result", 3)

	proofBefore := s.FakeProof(g)
	proofJSON, err := json.Marshal(proofBefore)
	if err != nil {
		t.Errorf("error during json marshal: %s", err.Error())
		return
	}

	var proofAfter MultiplicationProof
	err = json.Unmarshal(proofJSON, &proofAfter)
	if err != nil {
		t.Errorf("error during json unmarshal: %s", err.Error())
		return
	}

	if !s.VerifyProofStructure(proofAfter) {
		t.Error("json'ed proof structure rejected")
	}
}
