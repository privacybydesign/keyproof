package primeproofs

import "testing"
import "encoding/json"
import "github.com/mhe/gabi/big"

func TestExpStepFlowA(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for expStep proof testing")
		return
	}

	bitPederson := newPedersonSecret(g, "bit", big.NewInt(0))
	prePederson := newPedersonSecret(g, "pre", big.NewInt(2))
	postPederson := newPedersonSecret(g, "post", big.NewInt(2))
	mulPederson := newPedersonSecret(g, "mul", big.NewInt(3))
	modPederson := newPedersonSecret(g, "mod", big.NewInt(11))

	bases := newBaseMerge(&g, &bitPederson, &prePederson, &postPederson, &mulPederson, &modPederson)
	secrets := newSecretMerge(&bitPederson, &prePederson, &postPederson, &mulPederson, &modPederson)

	s := newExpStepStructure("bit", "pre", "post", "mul", "mod", 4)

	if !s.IsTrue(&secrets) {
		t.Error("Proof premise rejected")
	}

	listSecrets, commit := s.GenerateCommitmentsFromSecrets(g, []*big.Int{}, &bases, &secrets)
	proof := s.BuildProof(g, big.NewInt(12345), commit, &secrets)

	if !s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Proof structure rejected")
		return
	}

	bitProof := bitPederson.BuildProof(g, big.NewInt(12345))
	bitProof.SetName("bit")
	preProof := prePederson.BuildProof(g, big.NewInt(12345))
	preProof.SetName("pre")
	postProof := postPederson.BuildProof(g, big.NewInt(12345))
	postProof.SetName("post")
	mulProof := mulPederson.BuildProof(g, big.NewInt(12345))
	mulProof.SetName("mul")
	modProof := modPederson.BuildProof(g, big.NewInt(12345))
	modProof.SetName("mod")

	proofBases := newBaseMerge(&g, &bitProof, &preProof, &postProof, &mulProof, &modProof)

	listProof := s.GenerateCommitmentsFromProof(g, []*big.Int{}, big.NewInt(12345), &proofBases, proof)

	if !listCmp(listSecrets, listProof) {
		t.Error("Commitment lists differ.")
	}
}

func TestExpStepFlowB(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for expStep proof testing")
	}

	bitPederson := newPedersonSecret(g, "bit", big.NewInt(1))
	prePederson := newPedersonSecret(g, "pre", big.NewInt(2))
	postPederson := newPedersonSecret(g, "post", big.NewInt(6))
	mulPederson := newPedersonSecret(g, "mul", big.NewInt(3))
	modPederson := newPedersonSecret(g, "mod", big.NewInt(11))

	bases := newBaseMerge(&g, &bitPederson, &prePederson, &postPederson, &mulPederson, &modPederson)
	secrets := newSecretMerge(&bitPederson, &prePederson, &postPederson, &mulPederson, &modPederson)

	s := newExpStepStructure("bit", "pre", "post", "mul", "mod", 4)

	if !s.IsTrue(&secrets) {
		t.Error("Proof premise rejected")
	}

	listSecrets, commit := s.GenerateCommitmentsFromSecrets(g, []*big.Int{}, &bases, &secrets)
	proof := s.BuildProof(g, big.NewInt(12345), commit, &secrets)

	if !s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Proof structure rejected")
		return
	}

	bitProof := bitPederson.BuildProof(g, big.NewInt(12345))
	bitProof.SetName("bit")
	preProof := prePederson.BuildProof(g, big.NewInt(12345))
	preProof.SetName("pre")
	postProof := postPederson.BuildProof(g, big.NewInt(12345))
	postProof.SetName("post")
	mulProof := mulPederson.BuildProof(g, big.NewInt(12345))
	mulProof.SetName("mul")
	modProof := modPederson.BuildProof(g, big.NewInt(12345))
	modProof.SetName("mod")

	proofBases := newBaseMerge(&g, &bitProof, &preProof, &postProof, &mulProof, &modProof)

	listProof := s.GenerateCommitmentsFromProof(g, []*big.Int{}, big.NewInt(12345), &proofBases, proof)

	if !listCmp(listSecrets, listProof) {
		t.Error("Commitment lists differ.")
	}
}

func TestExpStepFake(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for expStep proof testing")
		return
	}

	s := newExpStepStructure("bit", "pre", "post", "mul", "mod", 4)

	proof := s.FakeProof(g, big.NewInt(12345))

	if !s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Fake proof rejected")
	}
}

func TestExpStepJSON(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for expStep proof testing")
		return
	}

	s := newExpStepStructure("bit", "pre", "post", "mul", "mod", 4)

	proofBefore := s.FakeProof(g, big.NewInt(12345))
	proofJSON, err := json.Marshal(proofBefore)
	if err != nil {
		t.Errorf("error during json marshal: %s", err.Error())
		return
	}

	var proofAfter expStepProof
	err = json.Unmarshal(proofJSON, &proofAfter)
	if err != nil {
		t.Errorf("error during json unmarshal: %s", err.Error())
		return
	}

	if !s.VerifyProofStructure(big.NewInt(12345), proofAfter) {
		t.Error("json'ed proof structure rejected")
	}
}

func TestExpStepVerifyProofStructure(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for expStep proof testing")
		return
	}

	s := newExpStepStructure("bit", "pre", "post", "mul", "mod", 4)

	proof := s.FakeProof(g, big.NewInt(12345))
	proof.Achallenge = nil
	if s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting missing achallenge.")
	}

	proof = s.FakeProof(g, big.NewInt(12345))
	proof.Bchallenge = nil
	if s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting missing bchallenge.")
	}

	proof = s.FakeProof(g, big.NewInt(12345))
	proof.Bchallenge.Add(proof.Bchallenge, big.NewInt(1))
	if s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting incorrect challenges.")
	}

	proof = s.FakeProof(g, big.NewInt(12345))
	proof.Aproof.BitHiderResult = nil
	if s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting corrupted aproof")
	}

	proof = s.FakeProof(g, big.NewInt(12345))
	proof.Bproof.BitHiderResult = nil
	if s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting corrupted bproof")
	}
}
