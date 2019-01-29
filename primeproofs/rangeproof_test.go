package primeproofs

import "testing"
import "encoding/json"
import "github.com/privacybydesign/gabi/big"

type RangeTestSecret struct {
	secrets     map[string]*big.Int
	randomizers map[string]*big.Int
}

func (rs *RangeTestSecret) GetSecret(name string) *big.Int {
	res, ok := rs.secrets[name]
	if ok {
		return res
	}
	return nil
}

func (rs *RangeTestSecret) GetRandomizer(name string) *big.Int {
	res, ok := rs.randomizers[name]
	if ok {
		return res
	}
	return nil
}

type RangeTestCommit struct {
	commits map[string]*big.Int
}

func (rc *RangeTestCommit) Names() (ret []string) {
	for name := range rc.commits {
		ret = append(ret, name)
	}
	return
}
func (rc *RangeTestCommit) GetBase(name string) *big.Int {
	res, ok := rc.commits[name]
	if ok {
		return res
	}
	return nil
}
func (rc *RangeTestCommit) Exp(ret *big.Int, name string, exp, P *big.Int) bool {
	base := rc.GetBase(name)
	ret.Exp(base, exp, P)
	return true
}

func listCmp(a []*big.Int, b []*big.Int) bool {
	if len(a) != len(b) {
		return false
	}
	for i, ai := range a {
		if ai == nil || b[i] == nil {
			return false
		}
		if ai.Cmp(b[i]) != 0 {
			return false
		}
	}
	return true
}

func TestRangeProofBasic(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for Range proof testing")
		return
	}

	Follower.(*TestFollower).count = 0

	var s RangeProofStructure
	s.Lhs = []LhsContribution{
		LhsContribution{"x", big.NewInt(1)},
	}
	s.Rhs = []RhsContribution{
		RhsContribution{"g", "x", 1},
	}
	s.rangeSecret = "x"
	s.l1 = 3
	s.l2 = 2

	var secret RangeTestSecret
	secret.secrets = map[string]*big.Int{
		"x": big.NewInt(7),
	}
	secret.randomizers = map[string]*big.Int{} // These shouldn't be neccessary, so detect use with a panic

	var commit RangeTestCommit
	commit.commits = map[string]*big.Int{
		"x": new(big.Int).Exp(g.g, big.NewInt(7), g.P),
	}

	bases := newBaseMerge(&g, &commit)

	if !s.IsTrue(g, &bases, &secret) {
		t.Error("Statement incorrectly declared false")
	}

	listSecret, rpcommit := s.GenerateCommitmentsFromSecrets(g, []*big.Int{}, &bases, &secret)

	if len(listSecret) != s.NumCommitments() {
		t.Error("NumCommitments is off")
	}

	if Follower.(*TestFollower).count != s.NumRangeProofs() {
		t.Error("Logging is off GenerateCommitmentsFromSecrets")
	}
	Follower.(*TestFollower).count = 0

	proof := s.BuildProof(g, big.NewInt(12345), rpcommit, &secret)

	if !s.VerifyProofStructure(proof) {
		t.Error("Proof structure rejected")
		return
	}

	listProof := s.GenerateCommitmentsFromProof(g, []*big.Int{}, big.NewInt(12345), &bases, proof)

	if Follower.(*TestFollower).count != s.NumRangeProofs() {
		t.Error("Logging is off on GenerateCommitmentsFromProof")
	}

	if !listCmp(listSecret, listProof) {
		t.Error("Commitment lists disagree")
	}
}

func TestRangeProofComplex(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for Range proof testing")
		return
	}

	Follower.(*TestFollower).count = 0

	var s RangeProofStructure
	s.Lhs = []LhsContribution{
		LhsContribution{"c", big.NewInt(1)},
	}
	s.Rhs = []RhsContribution{
		RhsContribution{"g", "x", 1},
		RhsContribution{"h", "xh", 1},
	}
	s.l1 = 3
	s.l2 = 2

	var secret RangeTestSecret
	secret.secrets = map[string]*big.Int{
		"x":  big.NewInt(7),
		"xh": big.NewInt(21),
	}
	secret.randomizers = map[string]*big.Int{} // These shouldn't be neccessary, so detect use with a panic

	var commit RangeTestCommit
	commit.commits = map[string]*big.Int{
		"c": new(big.Int).Mod(
			new(big.Int).Mul(
				new(big.Int).Exp(g.g, big.NewInt(7), g.P),
				new(big.Int).Exp(g.h, big.NewInt(21), g.P)),
			g.P),
	}

	bases := newBaseMerge(&g, &commit)

	if !s.IsTrue(g, &bases, &secret) {
		t.Error("Statement incorrectly declared false")
	}

	listSecret, rpcommit := s.GenerateCommitmentsFromSecrets(g, []*big.Int{}, &bases, &secret)

	if len(listSecret) != s.NumCommitments() {
		t.Error("NumCommitments is off")
	}

	if Follower.(*TestFollower).count != s.NumRangeProofs() {
		t.Error("Logging is off GenerateCommitmentsFromSecrets")
	}
	Follower.(*TestFollower).count = 0

	proof := s.BuildProof(g, big.NewInt(12345), rpcommit, &secret)

	if !s.VerifyProofStructure(proof) {
		t.Error("Proof structure rejected")
		return
	}

	listProof := s.GenerateCommitmentsFromProof(g, []*big.Int{}, big.NewInt(12345), &bases, proof)

	if Follower.(*TestFollower).count != s.NumRangeProofs() {
		t.Error("Logging is off on GenerateCommitmentsFromProof")
	}

	if !listCmp(listSecret, listProof) {
		t.Error("Commitment lists disagree")
	}
}

func TestRangeProofVerifyStructureEmpty(t *testing.T) {
	var proof RangeProof
	var s RangeProofStructure
	s.Lhs = []LhsContribution{
		LhsContribution{"c", big.NewInt(1)},
	}
	s.Rhs = []RhsContribution{
		RhsContribution{"g", "x", 1},
		RhsContribution{"h", "xh", 1},
	}
	s.l1 = 3
	s.l2 = 2

	if s.VerifyProofStructure(proof) {
		t.Error("Accepting empty proof")
	}
}

func TestRangeProofVerifyStructureMissingVar(t *testing.T) {
	var proof RangeProof
	var s RangeProofStructure
	s.Lhs = []LhsContribution{
		LhsContribution{"c", big.NewInt(1)},
	}
	s.Rhs = []RhsContribution{
		RhsContribution{"g", "x", 1},
		RhsContribution{"h", "xh", 1},
	}
	s.l1 = 3
	s.l2 = 2

	tlist := []*big.Int{}
	for i := 0; i < rangeProofIters; i++ {
		tlist = append(tlist, big.NewInt(1))
	}

	proof.Results = map[string][]*big.Int{
		"x": tlist,
	}

	if s.VerifyProofStructure(proof) {
		t.Error("Accepting missing variable in proof")
	}
}

func TestRangeProofVerifyStructureTooShortVar(t *testing.T) {
	var proof RangeProof
	var s RangeProofStructure
	s.Lhs = []LhsContribution{
		LhsContribution{"c", big.NewInt(1)},
	}
	s.Rhs = []RhsContribution{
		RhsContribution{"g", "x", 1},
		RhsContribution{"h", "xh", 1},
	}
	s.l1 = 3
	s.l2 = 2

	tlist := []*big.Int{}
	for i := 0; i < rangeProofIters; i++ {
		tlist = append(tlist, big.NewInt(1))
	}

	proof.Results = map[string][]*big.Int{
		"x":  tlist,
		"xh": tlist[:len(tlist)-1],
	}

	if s.VerifyProofStructure(proof) {
		t.Error("Accepting variable with too few results in proof")
	}

	proof.Results = map[string][]*big.Int{
		"x":  tlist[:len(tlist)-1],
		"xh": tlist,
	}
	if s.VerifyProofStructure(proof) {
		t.Error("Accepting variable with too few results in proof")
	}
}

func TestRangeProofVerifyStructureMissingNo(t *testing.T) {
	var proof RangeProof
	var s RangeProofStructure
	s.Lhs = []LhsContribution{
		LhsContribution{"c", big.NewInt(1)},
	}
	s.Rhs = []RhsContribution{
		RhsContribution{"g", "x", 1},
		RhsContribution{"h", "xh", 1},
	}
	s.l1 = 3
	s.l2 = 2

	tlist := []*big.Int{}
	for i := 0; i < rangeProofIters; i++ {
		tlist = append(tlist, big.NewInt(1))
	}

	hlist := []*big.Int{}
	for i := 0; i < rangeProofIters; i++ {
		hlist = append(hlist, big.NewInt(2))
	}

	hlist[rangeProofIters/2] = nil

	proof.Results = map[string][]*big.Int{
		"x":  hlist,
		"xh": tlist,
	}

	if s.VerifyProofStructure(proof) {
		t.Error("Accepting variable with missing numbers in proof")
	}
}

func TestRangeProofFake(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for Range proof testing")
		return
	}

	var s RangeProofStructure
	s.Lhs = []LhsContribution{
		LhsContribution{"c", big.NewInt(1)},
	}
	s.Rhs = []RhsContribution{
		RhsContribution{"g", "x", 1},
		RhsContribution{"h", "xh", 1},
	}
	s.l1 = 3
	s.l2 = 2

	proof := s.FakeProof(g)
	if !s.VerifyProofStructure(proof) {
		t.Error("Fake proof structure rejected.")
	}
}

func TestRangeProofJSON(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for Range proof testing")
		return
	}

	var s RangeProofStructure
	s.Lhs = []LhsContribution{
		LhsContribution{"c", big.NewInt(1)},
	}
	s.Rhs = []RhsContribution{
		RhsContribution{"g", "x", 1},
		RhsContribution{"h", "xh", 1},
	}
	s.l1 = 3
	s.l2 = 2

	proofBefore := s.FakeProof(g)
	proofJSON, err := json.Marshal(proofBefore)
	if err != nil {
		t.Errorf("error during json marshal: %s", err.Error())
		return
	}

	var proofAfter RangeProof
	err = json.Unmarshal(proofJSON, &proofAfter)
	if err != nil {
		t.Errorf("error during json unmarshal: %s", err.Error())
		return
	}

	if !s.VerifyProofStructure(proofAfter) {
		t.Error("json'ed proof structure rejected")
	}
}
