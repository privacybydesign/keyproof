package primeproofs

import "github.com/mhe/gabi/big"
import "testing"
import "encoding/json"

func TestExpProofFlow(t *testing.T) {
	const a = 2
	const b = 5
	const n = 11
	const r = -1

	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for exp proof testing")
		return
	}

	Follower.(*TestFollower).count = 0

	aPederson := newPedersonSecret(g, "a", big.NewInt(a))
	bPederson := newPedersonSecret(g, "b", big.NewInt(b))
	nPederson := newPedersonSecret(g, "n", big.NewInt(n))
	rPederson := newPedersonSecret(g, "r", big.NewInt(r))

	bases := newBaseMerge(&g, &aPederson, &bPederson, &nPederson, &rPederson)
	secrets := newSecretMerge(&aPederson, &bPederson, &nPederson, &rPederson)

	s := newExpProofStructure("a", "b", "n", "r", 4)

	if !s.IsTrue(&secrets) {
		t.Error("proof premise deemed false")
	}

	listSecrets, commit := s.GenerateCommitmentsFromSecrets(g, []*big.Int{}, &bases, &secrets)
	
	if len(listSecrets) != s.NumCommitments() {
		t.Error("NumCommitments is off")
	}

	if Follower.(*TestFollower).count != s.NumRangeProofs() {
		t.Error("Logging is off GenerateCommitmentsFromSecrets")
	}
	Follower.(*TestFollower).count = 0

	proof := s.BuildProof(g, big.NewInt(12345), commit, &secrets)

	if !s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("proof structure rejected")
		return
	}

	aProof := aPederson.BuildProof(g, big.NewInt(12345))
	aProof.SetName("a")
	bProof := bPederson.BuildProof(g, big.NewInt(12345))
	bProof.SetName("b")
	nProof := nPederson.BuildProof(g, big.NewInt(12345))
	nProof.SetName("n")
	rProof := rPederson.BuildProof(g, big.NewInt(12345))
	rProof.SetName("r")

	proofBases := newBaseMerge(&g, &aProof, &bProof, &nProof, &rProof)
	proofs := newProofMerge(&aProof, &bProof, &nProof, &rProof)

	listProof := s.GenerateCommitmentsFromProof(g, []*big.Int{}, big.NewInt(12345), &proofBases, &proofs, proof)

	if Follower.(*TestFollower).count != s.NumRangeProofs() {
		t.Error("Logging is off on GenerateCommitmentsFromProof")
	}

	if !listCmp(listSecrets, listProof) {
		t.Errorf("Commitment lists differ\n%v\n%v", listSecrets, listProof)
	}
}

func TestExpProofFake(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for exp proof testing")
		return
	}

	s := newExpProofStructure("a", "b", "n", "r", 4)

	proof := s.FakeProof(g, big.NewInt(12345))
	if !s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("fake proof structure rejected")
	}
}

func TestExpProofJSON(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for exp proof testing")
		return
	}

	s := newExpProofStructure("a", "b", "n", "r", 4)

	proofBefore := s.FakeProof(g, big.NewInt(12345))
	proofJSON, err := json.Marshal(proofBefore)
	if err != nil {
		t.Errorf("error during json marshal: %s", err.Error())
		return
	}

	var proofAfter expProof
	err = json.Unmarshal(proofJSON, &proofAfter)
	if err != nil {
		t.Errorf("error during json unmarshal: %s", err.Error())
		return
	}

	if !s.VerifyProofStructure(big.NewInt(12345), proofAfter) {
		t.Error("json'ed proof structure rejected")
	}
}

func TestExpProofVerifyStructure(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for exp proof testing")
		return
	}

	s := newExpProofStructure("a", "b", "n", "r", 4)

	proof := s.FakeProof(g, big.NewInt(12345))
	proof.ExpBitEqResult = nil
	if s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("accepting missing expbiteqresult")
	}

	proof = s.FakeProof(g, big.NewInt(12345))
	proof.ExpBitProofs = proof.ExpBitProofs[:len(proof.ExpBitProofs)-1]
	if s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("accepting too short expbitproofs")
	}

	proof = s.FakeProof(g, big.NewInt(12345))
	proof.ExpBitProofs[2].Commit = nil
	if s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("accepting corrupted expbitproof")
	}

	proof = s.FakeProof(g, big.NewInt(12345))
	proof.BasePowProofs = proof.BasePowProofs[:len(proof.BasePowProofs)-1]
	if s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("accepting too short basepowproofs")
	}

	proof = s.FakeProof(g, big.NewInt(12345))
	proof.BasePowProofs[1].Commit = nil
	if s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting corrupted basepowproofs")
	}

	proof = s.FakeProof(g, big.NewInt(12345))
	proof.BasePowRangeProofs = proof.BasePowRangeProofs[:len(proof.BasePowRangeProofs)-1]
	if s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting too short basepowrangeproofs")
	}

	proof = s.FakeProof(g, big.NewInt(12345))
	proof.BasePowRangeProofs[1].Results = nil
	if s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting corrupted basepowrangeproofs")
	}

	proof = s.FakeProof(g, big.NewInt(12345))
	proof.BasePowRelProofs = proof.BasePowRelProofs[:len(proof.BasePowRelProofs)-1]
	if s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting too short basepowrelproofs")
	}

	proof = s.FakeProof(g, big.NewInt(12345))
	proof.BasePowRelProofs[2].HiderResult = nil
	if s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting corrupted basepowrelproof")
	}

	proof = s.FakeProof(g, big.NewInt(12345))
	proof.StartProof.Commit = nil
	if s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting corrupted startproof")
	}

	proof = s.FakeProof(g, big.NewInt(12345))
	proof.InterResProofs = proof.InterResProofs[:len(proof.InterResProofs)-1]
	if s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting too short interresproofs")
	}

	proof = s.FakeProof(g, big.NewInt(12345))
	proof.InterResProofs[1].Commit = nil
	if s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting corrupted interresproof")
	}

	proof = s.FakeProof(g, big.NewInt(12345))
	proof.InterResRangeProofs = proof.InterResRangeProofs[:len(proof.InterResRangeProofs)-1]
	if s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting too short interresrangeproofs")
	}

	proof = s.FakeProof(g, big.NewInt(12345))
	proof.InterResRangeProofs[2].Results = nil
	if s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting corrupted interresrangeproofs")
	}

	proof = s.FakeProof(g, big.NewInt(12345))
	proof.InterStepsProofs = proof.InterStepsProofs[:len(proof.InterStepsProofs)-1]
	if s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting too short interstepsproof")
	}

	proof = s.FakeProof(g, big.NewInt(12345))
	proof.InterStepsProofs[2].Achallenge = nil
	if s.VerifyProofStructure(big.NewInt(12345), proof) {
		t.Error("Accepting corrupted interstepsproof")
	}
}
