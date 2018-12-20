package primeproofs

import "testing"
import "github.com/mhe/gabi/big"

type RepTestSecret struct {
	secrets     map[string]*big.Int
	randomizers map[string]*big.Int
}

func (rs *RepTestSecret) GetSecret(name string) *big.Int {
	res, ok := rs.secrets[name]
	if ok {
		return res
	}
	return nil
}

func (rs *RepTestSecret) GetRandomizer(name string) *big.Int {
	res, ok := rs.randomizers[name]
	if ok {
		return res
	}
	return nil
}

type RepTestProof struct {
	results map[string]*big.Int
}

func (rp *RepTestProof) GetResult(name string) *big.Int {
	res, ok := rp.results[name]
	if ok {
		return res
	}
	return nil
}

type RepTestCommit struct {
	commits map[string]*big.Int
}

func (rc *RepTestCommit) GetBase(name string) *big.Int {
	res, ok := rc.commits[name]
	if ok {
		return res
	}
	return nil
}

func TestRepresentationProofBasics(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for Representation proof testing")
		return
	}

	var s RepresentationProofStructure
	s.Lhs = []LhsContribution{
		LhsContribution{"x", big.NewInt(1)},
	}
	s.Rhs = []RhsContribution{
		RhsContribution{"g", "x", 1},
	}

	var secret RepTestSecret
	secret.secrets = map[string]*big.Int{"x": big.NewInt(10)}
	secret.randomizers = map[string]*big.Int{"x": big.NewInt(15)}

	var commit RepTestCommit
	commit.commits = map[string]*big.Int{"x": new(big.Int).Exp(g.g, secret.secrets["x"], g.P)}

	var proof RepTestProof
	proof.results = map[string]*big.Int{"x": big.NewInt(5)}

	bases := newBaseMerge(&g, &commit)

	listSecrets := s.GenerateCommitmentsFromSecrets(g, []*big.Int{}, &bases, &secret)
	listProofs := s.GenerateCommitmentsFromProof(g, []*big.Int{}, big.NewInt(1), &bases, &proof)

	if !s.IsTrue(g, &bases, &secret) {
		t.Error("Incorrect rejection of truth")
	}

	if len(listSecrets) != 1 {
		t.Error("listSecrets of wrong length")
	}
	if len(listProofs) != 1 {
		t.Error("listProofs of wrong length")
	}
	if listSecrets[0].Cmp(listProofs[0]) != 0 {
		t.Error("Commitment lists different")
	}
}

func TestRepresentationProofComplex(t *testing.T) {
	g, gok := buildGroup(big.NewInt(47))
	if !gok {
		t.Error("Failed to setup group for Representation proof testing")
		return
	}

	var s RepresentationProofStructure
	s.Lhs = []LhsContribution{
		LhsContribution{"c", big.NewInt(4)},
	}
	s.Rhs = []RhsContribution{
		RhsContribution{"g", "x", 2},
		RhsContribution{"h", "y", 1},
	}

	var secret RepTestSecret
	secret.secrets = map[string]*big.Int{
		"x": big.NewInt(4),
		"y": big.NewInt(2),
	}
	secret.randomizers = map[string]*big.Int{
		"x": big.NewInt(12),
		"y": big.NewInt(21),
	}

	var commit RepTestCommit
	commit.commits = map[string]*big.Int{
		"c": new(big.Int).Mod(
			new(big.Int).Mul(
				new(big.Int).Exp(g.g, big.NewInt(2), g.P),
				new(big.Int).Exp(g.h, big.NewInt(12), g.P)),
			g.P),
	}

	var proof RepTestProof
	proof.results = map[string]*big.Int{
		"x": big.NewInt(4),
		"y": big.NewInt(17),
	}

	bases := newBaseMerge(&g, &commit)

	listSecrets := s.GenerateCommitmentsFromSecrets(g, []*big.Int{}, &bases, &secret)
	listProofs := s.GenerateCommitmentsFromProof(g, []*big.Int{}, big.NewInt(2), &bases, &proof)

	if !s.IsTrue(g, &bases, &secret) {
		t.Error("Incorrect rejection of truth")
	}

	if len(listSecrets) != 1 {
		t.Error("listSecrets of wrong length")
	}
	if len(listProofs) != 1 {
		t.Error("listProofs of wrong length")
	}
	if listSecrets[0].Cmp(listProofs[0]) != 0 {
		t.Error("Commitment lists different")
	}
}
