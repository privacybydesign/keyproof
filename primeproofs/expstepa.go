package primeproofs

import "github.com/privacybydesign/keyproof/common"
import "github.com/privacybydesign/gabi/big"
import "strings"

type expStepAStructure struct {
	bitname     string
	prename     string
	postname    string
	myname      string
	bitRep      RepresentationProofStructure
	equalityRep RepresentationProofStructure
}

type expStepAProof struct {
	nameBit             string
	nameEquality        string
	BitHiderResult      *big.Int
	EqualityHiderResult *big.Int
}

type expStepACommit struct {
	nameBit                 string
	nameEquality            string
	bitHiderRandomizer      *big.Int
	equalityHider           *big.Int
	equalityHiderRandomizer *big.Int
}

func (p *expStepAProof) GetResult(name string) *big.Int {
	if name == p.nameBit {
		return p.BitHiderResult
	}
	if name == p.nameEquality {
		return p.EqualityHiderResult
	}
	return nil
}

func (c *expStepACommit) GetSecret(name string) *big.Int {
	if name == c.nameEquality {
		return c.equalityHider
	}
	return nil
}

func (c *expStepACommit) GetRandomizer(name string) *big.Int {
	if name == c.nameBit {
		return c.bitHiderRandomizer
	}
	if name == c.nameEquality {
		return c.equalityHiderRandomizer
	}
	return nil
}

func newExpStepAStructure(bitname, prename, postname string) expStepAStructure {
	var structure expStepAStructure
	structure.bitname = bitname
	structure.prename = prename
	structure.postname = postname
	structure.myname = strings.Join([]string{bitname, prename, postname, "expa"}, "_")
	structure.bitRep = RepresentationProofStructure{
		[]LhsContribution{
			LhsContribution{bitname, big.NewInt(1)},
		},
		[]RhsContribution{
			RhsContribution{"h", strings.Join([]string{bitname, "hider"}, "_"), 1},
		},
	}
	structure.equalityRep = RepresentationProofStructure{
		[]LhsContribution{
			LhsContribution{prename, big.NewInt(1)},
			LhsContribution{postname, big.NewInt(-1)},
		},
		[]RhsContribution{
			RhsContribution{"h", strings.Join([]string{structure.myname, "eqhider"}, "_"), 1},
		},
	}
	return structure
}

func (s *expStepAStructure) NumRangeProofs() int {
	return 0
}

func (s *expStepAStructure) NumCommitments() int {
	return s.bitRep.NumCommitments() + s.equalityRep.NumCommitments()
}

func (s *expStepAStructure) GenerateCommitmentsFromSecrets(g group, list []*big.Int, bases BaseLookup, secretdata SecretLookup) ([]*big.Int, expStepACommit) {
	var commit expStepACommit

	// Build commit structure
	commit.nameBit = strings.Join([]string{s.bitname, "hider"}, "_")
	commit.nameEquality = strings.Join([]string{s.myname, "eqhider"}, "_")
	commit.bitHiderRandomizer = common.RandomBigInt(g.order)
	commit.equalityHider = new(big.Int).Mod(
		new(big.Int).Sub(
			secretdata.GetSecret(strings.Join([]string{s.prename, "hider"}, "_")),
			secretdata.GetSecret(strings.Join([]string{s.postname, "hider"}, "_"))),
		g.order)
	commit.equalityHiderRandomizer = common.RandomBigInt(g.order)

	// inner secrets
	secrets := newSecretMerge(&commit, secretdata)

	// Generate commitments
	list = s.bitRep.GenerateCommitmentsFromSecrets(g, list, bases, &secrets)
	list = s.equalityRep.GenerateCommitmentsFromSecrets(g, list, bases, &secrets)

	return list, commit
}

func (s *expStepAStructure) BuildProof(g group, challenge *big.Int, commit expStepACommit, secretdata SecretLookup) expStepAProof {
	var proof expStepAProof

	// Build our results
	proof.BitHiderResult = new(big.Int).Mod(
		new(big.Int).Sub(
			commit.bitHiderRandomizer,
			new(big.Int).Mul(
				challenge,
				secretdata.GetSecret(strings.Join([]string{s.bitname, "hider"}, "_")))),
		g.order)
	proof.EqualityHiderResult = new(big.Int).Mod(
		new(big.Int).Sub(
			commit.equalityHiderRandomizer,
			new(big.Int).Mul(
				challenge,
				commit.equalityHider)),
		g.order)

	return proof
}

func (s *expStepAStructure) FakeProof(g group) expStepAProof {
	var proof expStepAProof

	proof.BitHiderResult = common.RandomBigInt(g.order)
	proof.EqualityHiderResult = common.RandomBigInt(g.order)

	return proof
}

func (s *expStepAStructure) VerifyProofStructure(proof expStepAProof) bool {
	return proof.BitHiderResult != nil && proof.EqualityHiderResult != nil
}

func (s *expStepAStructure) GenerateCommitmentsFromProof(g group, list []*big.Int, challenge *big.Int, bases BaseLookup, proof expStepAProof) []*big.Int {
	// inner proof data
	proof.nameBit = strings.Join([]string{s.bitname, "hider"}, "_")
	proof.nameEquality = strings.Join([]string{s.myname, "eqhider"}, "_")

	// Generate commitments
	list = s.bitRep.GenerateCommitmentsFromProof(g, list, challenge, bases, &proof)
	list = s.equalityRep.GenerateCommitmentsFromProof(g, list, challenge, bases, &proof)

	return list
}

func (s *expStepAStructure) IsTrue(secretdata SecretLookup) bool {
	if secretdata.GetSecret(s.bitname).Cmp(big.NewInt(0)) != 0 {
		return false
	}
	if secretdata.GetSecret(s.prename).Cmp(secretdata.GetSecret(s.postname)) != 0 {
		return false
	}
	return true
}
