package primeproofs

import "github.com/mhe/gabi/big"
import "strings"

type expStepBStructure struct {
	bitname    string
	mulname    string
	myname     string
	bitRep     RepresentationProofStructure
	mulRep     RepresentationProofStructure
	prePostMul MultiplicationProofStructure
}

type expStepBProof struct {
	bitname             string
	mulname             string
	mulhidername        string
	MulResult           *big.Int
	MulHiderResult      *big.Int
	BitHiderResult      *big.Int
	MultiplicationProof MultiplicationProof
}

type expStepBCommit struct {
	bitname              string
	mulname              string
	mulhidername         string
	MulRandomizer        *big.Int
	MulHiderRandomizer   *big.Int
	BitHiderRandomizer   *big.Int
	MultiplicationCommit MultiplicationProofCommit
}

func (p *expStepBProof) GetResult(name string) *big.Int {
	if name == p.bitname {
		return p.BitHiderResult
	}
	if name == p.mulname {
		return p.MulResult
	}
	if name == p.mulhidername {
		return p.MulHiderResult
	}
	return nil
}

func (c *expStepBCommit) GetSecret(name string) *big.Int {
	return nil
}

func (c *expStepBCommit) GetRandomizer(name string) *big.Int {
	if name == c.bitname {
		return c.BitHiderRandomizer
	}
	if name == c.mulname {
		return c.MulRandomizer
	}
	if name == c.mulhidername {
		return c.MulHiderRandomizer
	}
	return nil
}

func newExpStepBStructure(bitname, prename, postname, mulname, modname string, bitlen uint) expStepBStructure {
	var structure expStepBStructure
	structure.bitname = bitname
	structure.mulname = mulname
	structure.myname = strings.Join([]string{bitname, prename, postname, "expb"}, "_")
	structure.bitRep = RepresentationProofStructure{
		[]LhsContribution{
			LhsContribution{bitname, big.NewInt(1)},
			LhsContribution{"g", big.NewInt(-1)},
		},
		[]RhsContribution{
			RhsContribution{"h", strings.Join([]string{bitname, "hider"}, "_"), 1},
		},
	}
	structure.mulRep = newPedersonRepresentationProofStructure(mulname)
	structure.prePostMul = newMultiplicationProofStructure(mulname, prename, modname, postname, bitlen)
	return structure
}

func (s *expStepBStructure) GenerateCommitmentsFromSecrets(g group, list []*big.Int, bases BaseLookup, secretdata SecretLookup) ([]*big.Int, expStepBCommit) {
	var commit expStepBCommit

	// build up commit structure
	commit.bitname = strings.Join([]string{s.bitname, "hider"}, "_")
	commit.mulname = s.mulname
	commit.mulhidername = strings.Join([]string{s.mulname, "hider"}, "_")
	commit.MulRandomizer = randomBigInt(g.order)
	commit.MulHiderRandomizer = randomBigInt(g.order)
	commit.BitHiderRandomizer = randomBigInt(g.order)

	// Inner secrets
	secrets := newSecretMerge(&commit, secretdata)

	// Generate commitment list
	list = s.bitRep.GenerateCommitmentsFromSecrets(g, list, bases, &secrets)
	list = s.mulRep.GenerateCommitmentsFromSecrets(g, list, bases, &secrets)
	list, commit.MultiplicationCommit = s.prePostMul.GenerateCommitmentsFromSecrets(g, list, bases, &secrets)

	return list, commit
}

func (s *expStepBStructure) BuildProof(g group, challenge *big.Int, commit expStepBCommit, secretdata SecretLookup) expStepBProof {
	// inner secrets
	secrets := newSecretMerge(&commit, secretdata)

	// Build proof
	var proof expStepBProof
	proof.MulResult = new(big.Int).Mod(
		new(big.Int).Sub(
			commit.MulRandomizer,
			new(big.Int).Mul(
				challenge,
				secretdata.GetSecret(s.mulname))),
		g.order)
	proof.MulHiderResult = new(big.Int).Mod(
		new(big.Int).Sub(
			commit.MulHiderRandomizer,
			new(big.Int).Mul(
				challenge,
				secretdata.GetSecret(strings.Join([]string{s.mulname, "hider"}, "_")))),
		g.order)
	proof.BitHiderResult = new(big.Int).Mod(
		new(big.Int).Sub(
			commit.BitHiderRandomizer,
			new(big.Int).Mul(
				challenge,
				secretdata.GetSecret(strings.Join([]string{s.bitname, "hider"}, "_")))),
		g.order)
	proof.MultiplicationProof = s.prePostMul.BuildProof(g, challenge, commit.MultiplicationCommit, &secrets)
	return proof
}

func (s *expStepBStructure) FakeProof(g group) expStepBProof {
	var proof expStepBProof
	proof.MulResult = randomBigInt(g.order)
	proof.MulHiderResult = randomBigInt(g.order)
	proof.BitHiderResult = randomBigInt(g.order)
	proof.MultiplicationProof = s.prePostMul.FakeProof(g)
	return proof
}

func (s *expStepBStructure) VerifyProofStructure(proof expStepBProof) bool {
	if !s.prePostMul.VerifyProofStructure(proof.MultiplicationProof) {
		return false
	}

	return proof.MulResult != nil && proof.MulHiderResult != nil && proof.BitHiderResult != nil
}

func (s *expStepBStructure) GenerateCommitmentsFromProof(g group, list []*big.Int, challenge *big.Int, bases BaseLookup, proof expStepBProof) []*big.Int {
	// inner proof
	proof.bitname = strings.Join([]string{s.bitname, "hider"}, "_")
	proof.mulname = s.mulname
	proof.mulhidername = strings.Join([]string{s.mulname, "hider"}, "_")

	// Generate commitments
	list = s.bitRep.GenerateCommitmentsFromProof(g, list, challenge, bases, &proof)
	list = s.mulRep.GenerateCommitmentsFromProof(g, list, challenge, bases, &proof)
	list = s.prePostMul.GenerateCommitmentsFromProof(g, list, challenge, bases, &proof, proof.MultiplicationProof)

	return list
}

func (s *expStepBStructure) IsTrue(secretdata SecretLookup) bool {
	if secretdata.GetSecret(s.bitname).Cmp(big.NewInt(1)) != 0 {
		return false
	}
	return s.prePostMul.IsTrue(secretdata)
}
