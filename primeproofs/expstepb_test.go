package primeproofs

import "testing"
import "github.com/mhe/gabi/big"

func TestExpStepBFlow(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for expStepB proof testing")
	}

	bitPederson := newPedersonSecret(g, "bit", big.NewInt(1))
	prePederson := newPedersonSecret(g, "pre", big.NewInt(2))
	postPederson := newPedersonSecret(g, "post", big.NewInt(6))
	mulPederson := newPedersonSecret(g, "mul", big.NewInt(3))
	modPederson := newPedersonSecret(g, "mod", big.NewInt(11))

	bases := newBaseMerge(&g, &bitPederson, &prePederson, &postPederson, &mulPederson, &modPederson)
	secrets := newSecretMerge(&bitPederson, &prePederson, &postPederson, &mulPederson, &modPederson)

	s := newExpStepBStructure("bit", "pre", "post", "mul", "mod", 4)

	if !s.IsTrue(&secrets) {
		t.Error("Proof premis rejected")
	}

	listSecrets, commit := s.GenerateCommitmentsFromSecrets(g, []*big.Int{}, &bases, &secrets)
	proof := s.BuildProof(g, big.NewInt(12345), commit, &secrets)

	if !s.VerifyProofStructure(proof) {
		t.Error("Proof structure rejected")
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

func TestExpStepBFake(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for expStepB proof testing")
	}

	s := newExpStepBStructure("bit", "pre", "post", "mul", "mod", 4)

	proof := s.FakeProof(g)
	if !s.VerifyProofStructure(proof) {
		t.Error("Fake proof structure rejected")
	}
}

func TestExpStepBVerifyStructure(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for expStepB proof testing")
	}

	s := newExpStepBStructure("bit", "pre", "post", "mul", "mod", 4)

	proof := s.FakeProof(g)
	proof.MulResult = nil
	if s.VerifyProofStructure(proof) {
		t.Error("Accepting missing mulresult")
	}

	proof = s.FakeProof(g)
	proof.MulHiderResult = nil
	if s.VerifyProofStructure(proof) {
		t.Error("Accepting missing mulhiderresult")
	}

	proof = s.FakeProof(g)
	proof.BitHiderResult = nil
	if s.VerifyProofStructure(proof) {
		t.Error("Accepting missing bithiderresult")
	}

	proof = s.FakeProof(g)
	proof.MultiplicationProof.HiderResult = nil
	if s.VerifyProofStructure(proof) {
		t.Error("Accepting corrupted multiplicationproof")
	}
}
