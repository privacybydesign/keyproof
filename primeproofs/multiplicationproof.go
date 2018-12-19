package primeproofs

import "github.com/mhe/gabi/big"
import "strings"

type MultiplicationProofStructure struct {
	m1                 string
	m2                 string
	mod                string
	result             string
	myname             string
	multRepresentation RepresentationProofStructure
	multRange          RangeProofStructure
}

type MultiplicationProof struct {
	nameMod       string
	nameHider     string
	ModMultResult *big.Int
	HiderResult   *big.Int
	RangeProof    RangeProof
}

type MultiplicationProofCommit struct {
	nameMod           string
	nameHider         string
	ModMult           *big.Int
	ModMultRandomizer *big.Int
	Hider             *big.Int
	HiderRandomizer   *big.Int
	RangeCommit       RangeCommit
}

func (p *MultiplicationProof) GetResult(name string) *big.Int {
	if name == p.nameMod {
		return p.ModMultResult
	}
	if name == p.nameHider {
		return p.HiderResult
	}
	return nil
}

func (c *MultiplicationProofCommit) GetSecret(name string) *big.Int {
	if name == c.nameMod {
		return c.ModMult
	}
	if name == c.nameHider {
		return c.Hider
	}
	return nil
}

func (c *MultiplicationProofCommit) GetRandomizer(name string) *big.Int {
	if name == c.nameMod {
		return c.ModMultRandomizer
	}
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
	structure.multRange = RangeProofStructure{
		structure.multRepresentation,
		strings.Join([]string{structure.myname, "mod"}, "_"),
		0,
		l,
	}
	return structure
}

func (s *MultiplicationProofStructure) GenerateCommitmentsFromSecrets(g group, list []*big.Int, bases BaseLookup, secretdata SecretLookup) ([]*big.Int, MultiplicationProofCommit) {
	var commit MultiplicationProofCommit

	// Generate the neccesary commit data for our parts of the proof
	commit.nameMod = strings.Join([]string{s.myname, "mod"}, "_")
	commit.nameHider = strings.Join([]string{s.myname, "hider"}, "_")
	commit.ModMult = new(big.Int).Div(
		new(big.Int).Sub(
			new(big.Int).Mul(
				secretdata.GetSecret(s.m1),
				secretdata.GetSecret(s.m2)),
			secretdata.GetSecret(s.result)),
		secretdata.GetSecret(s.mod))
	commit.ModMultRandomizer = randomBigInt(g.order)
	commit.Hider = new(big.Int).Mod(
		new(big.Int).Add(
			new(big.Int).Sub(
				secretdata.GetSecret(strings.Join([]string{s.result, "hider"}, "_")),
				new(big.Int).Mul(
					secretdata.GetSecret(s.m1),
					secretdata.GetSecret(strings.Join([]string{s.m2, "hider"}, "_")))),
			new(big.Int).Mul(
				commit.ModMult,
				secretdata.GetSecret(strings.Join([]string{s.mod, "hider"}, "_")))),
		g.order)
	commit.HiderRandomizer = randomBigInt(g.order)

	// Build inner secrets
	secrets := newSecretMerge(&commit, secretdata)

	// Generate commitments for the two proofs
	list = s.multRepresentation.GenerateCommitmentsFromSecrets(g, list, bases, &secrets)
	list, commit.RangeCommit = s.multRange.GenerateCommitmentsFromSecrets(g, list, bases, &secrets)

	return list, commit
}

func (s *MultiplicationProofStructure) BuildProof(g group, challenge *big.Int, commit MultiplicationProofCommit, secretdata SecretLookup) MultiplicationProof {
	var proof MultiplicationProof

	// Generate the proofs
	rangeSecrets := newSecretMerge(&commit, secretdata)
	proof.RangeProof = s.multRange.BuildProof(g, challenge, commit.RangeCommit, &rangeSecrets)
	proof.ModMultResult = new(big.Int).Mod(
		new(big.Int).Sub(
			commit.ModMultRandomizer,
			new(big.Int).Mul(
				challenge,
				commit.ModMult)),
		g.order)
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
	proof.RangeProof = s.multRange.FakeProof(g)
	proof.ModMultResult = randomBigInt(g.order)
	proof.HiderResult = randomBigInt(g.order)
	return proof
}

func (s *MultiplicationProofStructure) VerifyProofStructure(proof MultiplicationProof) bool {
	if !s.multRange.VerifyProofStructure(proof.RangeProof) {
		return false
	}
	if proof.ModMultResult == nil || proof.HiderResult == nil {
		return false
	}
	return true
}

func (s *MultiplicationProofStructure) GenerateCommitmentsFromProof(g group, list []*big.Int, challenge *big.Int, bases BaseLookup, proofdata ProofLookup, proof MultiplicationProof) []*big.Int {
	// Build inner proof lookup
	proof.nameMod = strings.Join([]string{s.myname, "mod"}, "_")
	proof.nameHider = strings.Join([]string{s.myname, "hider"}, "_")
	proofs := newProofMerge(&proof, proofdata)

	// And regenerate the commitments
	list = s.multRepresentation.GenerateCommitmentsFromProof(g, list, challenge, bases, &proofs)
	list = s.multRange.GenerateCommitmentsFromProof(g, list, challenge, bases, proof.RangeProof)

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

	return mod.Cmp(big.NewInt(0)) == 0 && uint(div.BitLen()) <= s.multRange.l2
}
