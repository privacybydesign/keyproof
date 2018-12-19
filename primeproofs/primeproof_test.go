package primeproofs

import "testing"
import "github.com/mhe/gabi/big"
import "fmt"

func TestPrimeProofFlow(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for Prime proof testing")
	}

	s := newPrimeProofStructure("p", 4)

	const p = 11
	pCommit := newPedersonSecret(g, "p", big.NewInt(p))
	bases := newBaseMerge(&g, &pCommit)

	listSecrets, commit := s.GenerateCommitmentsFromSecrets(g, []*big.Int{}, &bases, &pCommit)
	proof := s.BuildProof(g, big.NewInt(12345), commit, &pCommit)
	pProof := pCommit.BuildProof(g, big.NewInt(12345))
	pProof.SetName("p")

	basesProof := newBaseMerge(&g, &pProof)

	if !s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Proof structure rejected.\n")
	}

	listProof := s.GenerateCommitmentsFromProof(g, []*big.Int{}, big.NewInt(12345), &basesProof, &pProof, proof)
	if !listCmp(listSecrets, listProof) {
		fmt.Printf("%v\n%v\n", listSecrets, listProof)
		t.Error("Commitment lists differ.")
	}
}

func TestPrimeProofFake(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for Prime proof testing")
	}

	s := newPrimeProofStructure("p", 4)

	proof := s.FakeProof(g, big.NewInt(12345))

	if !s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Fake proof structure rejected.")
	}
}

func TestPrimeProofVerify(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for Prime proof testing")
	}

	s := newPrimeProofStructure("p", 4)

	proof := s.FakeProof(g, big.NewInt(12345))
	proof.preaCommit.Commit = nil
	if s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting wrong prea pederson proof")
	}

	proof = s.FakeProof(g, big.NewInt(12345))
	proof.halfPCommit.Commit = nil
	if s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting wrong halfp pederson proof")
	}

	proof = s.FakeProof(g, big.NewInt(12345))
	proof.aCommit.Commit = nil
	if s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting wrong a pederson proof")
	}

	proof = s.FakeProof(g, big.NewInt(12345))
	proof.anegCommit.Commit = nil
	if s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting wrong aneg pederson proof")
	}

	proof = s.FakeProof(g, big.NewInt(12345))
	proof.aResCommit.Commit = nil
	if s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting wrong aRes pederson proof")
	}

	proof = s.FakeProof(g, big.NewInt(12345))
	proof.anegResCommit.Commit = nil
	if s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting wrong anegRes pederson proof")
	}

	proof = s.FakeProof(g, big.NewInt(12345))
	proof.preaModResult = nil
	if s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting missing preamodresult")
	}

	proof = s.FakeProof(g, big.NewInt(12345))
	proof.preaHiderResult = nil
	if s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting missing preahiderresult")
	}

	proof = s.FakeProof(g, big.NewInt(12345))
	proof.aPlus1Result = nil
	if s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting missing aPlus1Result")
	}

	proof = s.FakeProof(g, big.NewInt(12345))
	proof.aMin1Result = nil
	if s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting missing aMin1Result")
	}

	proof = s.FakeProof(g, big.NewInt(12345))
	proof.aPlus1Challenge = nil
	if s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting missing aPlus1Challenge")
	}

	proof = s.FakeProof(g, big.NewInt(12345))
	proof.aMin1Challenge = nil
	if s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting missing aMin1Challenge")
	}

	proof = s.FakeProof(g, big.NewInt(12345))
	proof.aMin1Challenge.Set(big.NewInt(1))
	if s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting incorrect challenges")
	}

	proof = s.FakeProof(g, big.NewInt(12345))
	proof.preaRangeProof.Results = nil
	if s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting wrong prearangeproof")
	}

	proof = s.FakeProof(g, big.NewInt(12345))
	proof.aRangeProof.Results = nil
	if s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting wrong arangeproof")
	}

	proof = s.FakeProof(g, big.NewInt(12345))
	proof.anegRangeProof.Results = nil
	if s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting wrong anegrangeproof")
	}

	proof = s.FakeProof(g, big.NewInt(12345))
	proof.preaModRangeProof.Results = nil
	if s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting wrong preamodrangeproof")
	}

	proof = s.FakeProof(g, big.NewInt(12345))
	proof.aExpProof.ExpBitEqResult = nil
	if s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting wrong aexpproof")
	}

	proof = s.FakeProof(g, big.NewInt(12345))
	proof.anegExpProof.ExpBitEqResult = nil
	if s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting wrong anegexpproof")
	}
}
