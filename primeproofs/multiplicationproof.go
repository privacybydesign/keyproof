package primeproofs

import "github.com/privacybydesign/keyproof/common"
import "github.com/privacybydesign/gabi/big"
import "strings"

type MultiplicationProofStructure struct {
	m1                    string
	m2                    string
	mod                   string
	result                string
	myname                string
	multRepresentation    RepresentationProofStructure
	modMultRepresentation RepresentationProofStructure
	modMultRange          RangeProofStructure
}

type MultiplicationProof struct {
	nameHider    string
	ModMultProof PedersonProof
	HiderResult  *big.Int
	RangeProof   RangeProof
}

type MultiplicationProofCommit struct {
	nameHider       string
	modMultPederson PedersonSecret
	Hider           *big.Int
	HiderRandomizer *big.Int
	RangeCommit     RangeCommit
}

func (p *MultiplicationProof) GetResult(name string) *big.Int {
	if name == p.nameHider {
		return p.HiderResult
	}
	return nil
}

func (c *MultiplicationProofCommit) GetSecret(name string) *big.Int {
	if name == c.nameHider {
		return c.Hider
	}
	return nil
}

func (c *MultiplicationProofCommit) GetRandomizer(name string) *big.Int {
	if name == c.nameHider {
		return c.HiderRandomizer
	}
	return nil
}

// Note, m1, m2, mod and result should be names of pederson commitments
func newMultiplicationProofStructure(m1, m2, mod, result string, l uint) MultiplicationProofStructure {
	var structure MultiplicationProofStructure
	structure.m1 = m1
	structure.m2 = m2
	structure.mod = mod
	structure.result = result
	structure.myname = strings.Join([]string{m1, m2, mod, result, "mul"}, "_")
	structure.multRepresentation = RepresentationProofStructure{
		[]LhsContribution{
			LhsContribution{result, big.NewInt(1)},
		},
		[]RhsContribution{
			RhsContribution{m2, m1, 1},
			RhsContribution{mod, strings.Join([]string{structure.myname, "mod"}, "_"), -1},
			RhsContribution{"h", strings.Join([]string{structure.myname, "hider"}, "_"), 1},
		},
	}
	structure.modMultRepresentation = newPedersonRepresentationProofStructure(strings.Join([]string{structure.myname, "mod"}, "_"))
	structure.modMultRange = newPedersonRangeProofStructure(strings.Join([]string{structure.myname, "mod"}, "_"), 0, l)
	return structure
}

func (s *MultiplicationProofStructure) NumRangeProofs() int {
	return 1
}

func (s *MultiplicationProofStructure) NumCommitments() int {
	return s.multRepresentation.NumCommitments() +
		s.modMultRepresentation.NumCommitments() +
		s.modMultRange.NumCommitments() +
		1
}

func (s *MultiplicationProofStructure) GenerateCommitmentsFromSecrets(g group, list []*big.Int, bases BaseLookup, secretdata SecretLookup) ([]*big.Int, MultiplicationProofCommit) {
	var commit MultiplicationProofCommit

	// Generate the neccesary commit data for our parts of the proof
	commit.nameHider = strings.Join([]string{s.myname, "hider"}, "_")
	commit.modMultPederson = newPedersonSecret(
		g,
		strings.Join([]string{s.myname, "mod"}, "_"),
		new(big.Int).Div(
			new(big.Int).Sub(
				new(big.Int).Mul(
					secretdata.GetSecret(s.m1),
					secretdata.GetSecret(s.m2)),
				secretdata.GetSecret(s.result)),
			secretdata.GetSecret(s.mod)))
	commit.Hider = new(big.Int).Mod(
		new(big.Int).Add(
			new(big.Int).Sub(
				secretdata.GetSecret(strings.Join([]string{s.result, "hider"}, "_")),
				new(big.Int).Mul(
					secretdata.GetSecret(s.m1),
					secretdata.GetSecret(strings.Join([]string{s.m2, "hider"}, "_")))),
			new(big.Int).Mul(
				commit.modMultPederson.secret,
				secretdata.GetSecret(strings.Join([]string{s.mod, "hider"}, "_")))),
		g.order)
	commit.HiderRandomizer = common.RandomBigInt(g.order)

	// Build inner secrets
	secrets := newSecretMerge(&commit, &commit.modMultPederson, secretdata)

	// Generate commitments for the two proofs
	list = commit.modMultPederson.GenerateCommitments(list)
	list = s.multRepresentation.GenerateCommitmentsFromSecrets(g, list, bases, &secrets)
	list = s.modMultRepresentation.GenerateCommitmentsFromSecrets(g, list, bases, &secrets)
	list, commit.RangeCommit = s.modMultRange.GenerateCommitmentsFromSecrets(g, list, bases, &secrets)

	return list, commit
}

func (s *MultiplicationProofStructure) BuildProof(g group, challenge *big.Int, commit MultiplicationProofCommit, secretdata SecretLookup) MultiplicationProof {
	var proof MultiplicationProof

	// Generate the proofs
	rangeSecrets := newSecretMerge(&commit, &commit.modMultPederson, secretdata)
	proof.RangeProof = s.modMultRange.BuildProof(g, challenge, commit.RangeCommit, &rangeSecrets)
	proof.ModMultProof = commit.modMultPederson.BuildProof(g, challenge)
	proof.HiderResult = new(big.Int).Mod(
		new(big.Int).Sub(
			commit.HiderRandomizer,
			new(big.Int).Mul(
				challenge,
				commit.Hider)),
		g.order)

	return proof
}

func (s *MultiplicationProofStructure) FakeProof(g group) MultiplicationProof {
	var proof MultiplicationProof
	proof.RangeProof = s.modMultRange.FakeProof(g)
	proof.ModMultProof = newPedersonFakeProof(g)
	proof.HiderResult = common.RandomBigInt(g.order)
	return proof
}

func (s *MultiplicationProofStructure) VerifyProofStructure(proof MultiplicationProof) bool {
	if !s.modMultRange.VerifyProofStructure(proof.RangeProof) {
		return false
	}
	if !proof.ModMultProof.VerifyStructure() || proof.HiderResult == nil {
		return false
	}
	return true
}

func (s *MultiplicationProofStructure) GenerateCommitmentsFromProof(g group, list []*big.Int, challenge *big.Int, bases BaseLookup, proofdata ProofLookup, proof MultiplicationProof) []*big.Int {
	// Build inner proof lookup
	proof.ModMultProof.SetName(strings.Join([]string{s.myname, "mod"}, "_"))
	proof.nameHider = strings.Join([]string{s.myname, "hider"}, "_")
	proofs := newProofMerge(&proof, &proof.ModMultProof, proofdata)
	innerBases := newBaseMerge(&proof.ModMultProof, bases)

	// And regenerate the commitments
	list = proof.ModMultProof.GenerateCommitments(list)
	list = s.multRepresentation.GenerateCommitmentsFromProof(g, list, challenge, &innerBases, &proofs)
	list = s.modMultRepresentation.GenerateCommitmentsFromProof(g, list, challenge, &innerBases, &proofs)
	list = s.modMultRange.GenerateCommitmentsFromProof(g, list, challenge, &innerBases, proof.RangeProof)

	return list
}

func (s *MultiplicationProofStructure) IsTrue(secretdata SecretLookup) bool {
	div := new(big.Int)
	mod := new(big.Int)

	div.DivMod(
		new(big.Int).Sub(
			new(big.Int).Mul(
				secretdata.GetSecret(s.m1),
				secretdata.GetSecret(s.m2)),
			secretdata.GetSecret(s.result)),
		secretdata.GetSecret(s.mod),
		mod)

	return mod.Cmp(big.NewInt(0)) == 0 && uint(div.BitLen()) <= s.modMultRange.l2
}
