package primeproofs

import "testing"
import "encoding/json"
import "github.com/mhe/gabi/big"

func TestExpStepAFlow(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for expStepA proof testing")
		return
	}

	bitPederson := newPedersonSecret(g, "bit", big.NewInt(0))
	prePederson := newPedersonSecret(g, "pre", big.NewInt(5))
	postPederson := newPedersonSecret(g, "post", big.NewInt(5))

	bases := newBaseMerge(&g, &bitPederson, &prePederson, &postPederson)
	secrets := newSecretMerge(&bitPederson, &prePederson, &postPederson)

	s := newExpStepAStructure("bit", "pre", "post")

	if !s.IsTrue(&secrets) {
		t.Error("Statement validity rejected")
	}

	listSecrets, commit := s.GenerateCommitmentsFromSecrets(g, []*big.Int{}, &bases, &secrets)
	proof := s.BuildProof(g, big.NewInt(12345), commit, &secrets)

	if !s.VerifyProofStructure(proof) {
		t.Error("Proof structure rejected.")
		return
	}

	bitProof := bitPederson.BuildProof(g, big.NewInt(12345))
	bitProof.SetName("bit")
	preProof := prePederson.BuildProof(g, big.NewInt(12345))
	preProof.SetName("pre")
	postProof := postPederson.BuildProof(g, big.NewInt(12345))
	postProof.SetName("post")

	proofBases := newBaseMerge(&g, &bitProof, &preProof, &postProof)

	listProof := s.GenerateCommitmentsFromProof(g, []*big.Int{}, big.NewInt(12345), &proofBases, proof)
	if !listCmp(listSecrets, listProof) {
		t.Error("Commitment lists differ.")
	}
}

func TestExpStepAFake(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for expStepA proof testing")
		return
	}

	s := newExpStepAStructure("bit", "pre", "post")

	proof := s.FakeProof(g)
	if !s.VerifyProofStructure(proof) {
		t.Error("Fake proof structure rejected.")
	}
}

func TestExpStepAJSON(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for expStepA proof testing")
		return
	}

	s := newExpStepAStructure("bit", "pre", "post")

	proofBefore := s.FakeProof(g)
	proofJSON, err := json.Marshal(proofBefore)
	if err != nil {
		t.Errorf("error during json marshal: %s", err.Error())
		return
	}

	var proofAfter expStepAProof
	err = json.Unmarshal(proofJSON, &proofAfter)
	if err != nil {
		t.Errorf("error during json unmarshal: %s", err.Error())
		return
	}

	if !s.VerifyProofStructure(proofAfter) {
		t.Error("json'ed proof structure rejected.")
	}
}

func TestExpStepAVerifyStructure(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for expStepA proof testing")
		return
	}

	s := newExpStepAStructure("bit", "pre", "post")

	proof := s.FakeProof(g)

	proof.BitHiderResult = nil
	if s.VerifyProofStructure(proof) {
		t.Error("Accepting missing bithiderresult")
	}

	proof.BitHiderResult = proof.EqualityHiderResult
	proof.EqualityHiderResult = nil
	if s.VerifyProofStructure(proof) {
		t.Error("Accepting missing equalityhiderresult")
	}
}
