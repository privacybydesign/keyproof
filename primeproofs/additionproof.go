package primeproofs

import "github.com/mhe/gabi/big"
import "strings"

type AdditionProofStructure struct {
	a1                string
	a2                string
	mod               string
	result            string
	myname            string
	addRepresentation RepresentationProofStructure
	addRange          RangeProofStructure
}

type AdditionProof struct {
	nameMod      string
	nameHider    string
	ModAddResult *big.Int
	HiderResult  *big.Int
	RangeProof   RangeProof
}

type AdditionProofCommit struct {
	nameMod          string
	nameHider        string
	ModAdd           *big.Int
	ModAddRandomizer *big.Int
	Hider            *big.Int
	HiderRandomizer  *big.Int
	RangeCommit      RangeCommit
}

func (p *AdditionProof) GetResult(name string) *big.Int {
	if name == p.nameMod {
		return p.ModAddResult
	}
	if name == p.nameHider {
		return p.HiderResult
	}
	return nil
}

func (c *AdditionProofCommit) GetSecret(name string) *big.Int {
	if name == c.nameMod {
		return c.ModAdd
	}
	if name == c.nameHider {
		return c.Hider
	}
	return nil
}

func (c *AdditionProofCommit) GetRandomizer(name string) *big.Int {
	if name == c.nameMod {
		return c.ModAddRandomizer
	}
	if name == c.nameHider {
		return c.HiderRandomizer
	}
	return nil
}

func newAdditionProofStructure(a1, a2, mod, result string, l uint) AdditionProofStructure {
	var structure AdditionProofStructure
	structure.a1 = a1
	structure.a2 = a2
	structure.mod = mod
	structure.result = result
	structure.myname = strings.Join([]string{a1, a2, mod, result, "add"}, "_")
	structure.addRepresentation = RepresentationProofStructure{
		[]LhsContribution{
			LhsContribution{result, big.NewInt(1)},
			LhsContribution{a1, big.NewInt(-1)},
			LhsContribution{a2, big.NewInt(-1)},
		},
		[]RhsContribution{
			RhsContribution{mod, strings.Join([]string{structure.myname, "mod"}, "_"), 1},
			RhsContribution{"h", strings.Join([]string{structure.myname, "hider"}, "_"), 1},
		},
	}
	structure.addRange = RangeProofStructure{
		structure.addRepresentation,
		strings.Join([]string{structure.myname, "mod"}, "_"),
		0,
		l,
	}
	return structure
}

func (s *AdditionProofStructure) GenerateCommitmentsFromSecrets(g group, list []*big.Int, bases BaseLookup, secretdata SecretLookup) ([]*big.Int, AdditionProofCommit) {
	var commit AdditionProofCommit

	// Generate needed commit data
	commit.nameMod = strings.Join([]string{s.myname, "mod"}, "_")
	commit.nameHider = strings.Join([]string{s.myname, "hider"}, "_")
	commit.ModAdd = new(big.Int).Div(
		new(big.Int).Sub(
			secretdata.GetSecret(s.result),
			new(big.Int).Add(
				secretdata.GetSecret(s.a1),
				secretdata.GetSecret(s.a2))),
		secretdata.GetSecret(s.mod))
	commit.ModAddRandomizer = randomBigInt(g.order)
	commit.Hider = new(big.Int).Mod(
		new(big.Int).Sub(
			secretdata.GetSecret(strings.Join([]string{s.result, "hider"}, "_")),
			new(big.Int).Add(
				new(big.Int).Add(
					secretdata.GetSecret(strings.Join([]string{s.a1, "hider"}, "_")),
					secretdata.GetSecret(strings.Join([]string{s.a2, "hider"}, "_"))),
				new(big.Int).Mul(
					secretdata.GetSecret(strings.Join([]string{s.mod, "hider"}, "_")),
					commit.ModAdd))),
		g.order)
	commit.HiderRandomizer = randomBigInt(g.order)

	// build inner secrets
	secrets := newSecretMerge(&commit, secretdata)

	// And build commits
	list = s.addRepresentation.GenerateCommitmentsFromSecrets(g, list, bases, &secrets)
	list, commit.RangeCommit = s.addRange.GenerateCommitmentsFromSecrets(g, list, bases, &secrets)

	return list, commit
}

func (s *AdditionProofStructure) BuildProof(g group, challenge *big.Int, commit AdditionProofCommit, secretdata SecretLookup) AdditionProof {
	var proof AdditionProof

	rangeSecrets := newSecretMerge(&commit, secretdata)
	proof.RangeProof = s.addRange.BuildProof(g, challenge, commit.RangeCommit, &rangeSecrets)
	proof.ModAddResult = new(big.Int).Mod(
		new(big.Int).Sub(
			commit.ModAddRandomizer,
			new(big.Int).Mul(
				challenge,
				commit.ModAdd)),
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

func (s *AdditionProofStructure) FakeProof(g group) AdditionProof {
	var proof AdditionProof

	proof.RangeProof = s.addRange.FakeProof(g)
	proof.ModAddResult = randomBigInt(g.order)
	proof.HiderResult = randomBigInt(g.order)

	return proof
}

func (s *AdditionProofStructure) VerifyProofStructure(proof AdditionProof) bool {
	if !s.addRange.VerifyProofStructure(proof.RangeProof) {
		return false
	}
	if proof.ModAddResult == nil || proof.HiderResult == nil {
		return false
	}
	return true
}

func (s *AdditionProofStructure) GenerateCommitmentsFromProof(g group, list []*big.Int, challenge *big.Int, bases BaseLookup, proofdata ProofLookup, proof AdditionProof) []*big.Int {
	// build inner proof lookup
	proof.nameMod = strings.Join([]string{s.myname, "mod"}, "_")
	proof.nameHider = strings.Join([]string{s.myname, "hider"}, "_")
	proofs := newProofMerge(&proof, proofdata)

	// build commitments
	list = s.addRepresentation.GenerateCommitmentsFromProof(g, list, challenge, bases, &proofs)
	list = s.addRange.GenerateCommitmentsFromProof(g, list, challenge, bases, proof.RangeProof)

	return list
}

func (s *AdditionProofStructure) IsTrue(secretdata SecretLookup) bool {
	div := new(big.Int)
	mod := new(big.Int)

	div.DivMod(
		new(big.Int).Sub(
			secretdata.GetSecret(s.result),
			new(big.Int).Add(
				secretdata.GetSecret(s.a1),
				secretdata.GetSecret(s.a2))),
		secretdata.GetSecret(s.mod),
		mod)

	return mod.Cmp(big.NewInt(0)) == 0 && uint(div.BitLen()) <= s.addRange.l2
}
