package primeproofs

import "github.com/mhe/gabi/big"
import "strings"

type PrimeProofStructure struct {
	primeName string
	myname    string
	bitlen    uint

	halfPRep RepresentationProofStructure

	preaRep   RepresentationProofStructure
	preaRange RangeProofStructure

	aRep   RepresentationProofStructure
	aRange RangeProofStructure

	anegRep   RepresentationProofStructure
	anegRange RangeProofStructure

	aResRep      RepresentationProofStructure
	aPlus1ResRep RepresentationProofStructure
	aMin1ResRep  RepresentationProofStructure

	anegResRep RepresentationProofStructure

	aExp    expProofStructure
	anegExp expProofStructure
}

type PrimeProof struct {
	namePreaMod   string
	namePreaHider string
	nameAplus1    string
	nameAmin1     string

	halfPCommit   PedersonProof
	preaCommit    PedersonProof
	aCommit       PedersonProof
	anegCommit    PedersonProof
	aResCommit    PedersonProof
	anegResCommit PedersonProof

	preaModResult   *big.Int
	preaHiderResult *big.Int

	aPlus1Result    *big.Int
	aMin1Result     *big.Int
	aPlus1Challenge *big.Int
	aMin1Challenge  *big.Int

	preaRangeProof    RangeProof
	aRangeProof       RangeProof
	anegRangeProof    RangeProof
	preaModRangeProof RangeProof

	aExpProof    expProof
	anegExpProof expProof
}

type PrimeProofCommit struct {
	namePreaMod   string
	namePreaHider string
	nameAValid    string
	nameAInvalid  string

	halfPPederson   PedersonSecret
	preaPederson    PedersonSecret
	aPederson       PedersonSecret
	anegPederson    PedersonSecret
	aResPederson    PedersonSecret
	anegResPederson PedersonSecret

	preaMod             *big.Int
	preaModRandomizer   *big.Int
	preaHider           *big.Int
	preaHiderRandomizer *big.Int

	aValid            *big.Int
	aValidRandomizer  *big.Int
	aInvalidResult    *big.Int
	aInvalidChallenge *big.Int
	aPositive         bool

	preaRangeCommit    RangeCommit
	aRangeCommit       RangeCommit
	anegRangeCommit    RangeCommit
	preaModRangeCommit RangeCommit

	aExpCommit    expProofCommit
	anegExpCommit expProofCommit
}

func (p *PrimeProof) GetResult(name string) *big.Int {
	if name == p.namePreaMod {
		return p.preaModResult
	}
	if name == p.namePreaHider {
		return p.preaHiderResult
	}
	if name == p.nameAplus1 {
		return p.aPlus1Result
	}
	if name == p.nameAmin1 {
		return p.aMin1Result
	}
	return nil
}

func (c *PrimeProofCommit) GetSecret(name string) *big.Int {
	if name == c.namePreaMod {
		return c.preaMod
	}
	if name == c.namePreaHider {
		return c.preaHider
	}
	if name == c.nameAValid {
		return c.aValid
	}
	return nil
}

func (c *PrimeProofCommit) GetRandomizer(name string) *big.Int {
	if name == c.namePreaMod {
		return c.preaModRandomizer
	}
	if name == c.namePreaHider {
		return c.preaHiderRandomizer
	}
	if name == c.nameAValid {
		return c.aValidRandomizer
	}
	return nil
}

func (c *PrimeProofCommit) GetResult(name string) *big.Int {
	if name == c.nameAInvalid {
		return c.aInvalidResult
	}
	return nil
}

func newPrimeProofStructure(name string, bitlen uint) PrimeProofStructure {
	var structure PrimeProofStructure
	structure.primeName = name
	structure.myname = strings.Join([]string{name, "primeproof"}, "_")
	structure.bitlen = bitlen

	structure.halfPRep = RepresentationProofStructure{
		[]LhsContribution{
			LhsContribution{name, big.NewInt(1)},
			LhsContribution{strings.Join([]string{structure.myname, "halfp"}, "_"), big.NewInt(-2)},
			LhsContribution{"g", big.NewInt(-1)},
		},
		[]RhsContribution{
			RhsContribution{"h", strings.Join([]string{name, "hider"}, "_"), 1},
			RhsContribution{"h", strings.Join([]string{structure.myname, "halfp", "hider"}, "_"), -2},
		},
	}

	structure.preaRep = newPedersonRepresentationProofStructure(strings.Join([]string{structure.myname, "prea"}, "_"))
	structure.preaRange = newPedersonRangeProofStructure(strings.Join([]string{structure.myname, "prea"}, "_"), 0, bitlen)

	structure.aRep = newPedersonRepresentationProofStructure(strings.Join([]string{structure.myname, "a"}, "_"))
	structure.aRange = newPedersonRangeProofStructure(strings.Join([]string{structure.myname, "a"}, "_"), 0, bitlen)

	structure.anegRep = newPedersonRepresentationProofStructure(strings.Join([]string{structure.myname, "aneg"}, "_"))
	structure.anegRange = newPedersonRangeProofStructure(strings.Join([]string{structure.myname, "aneg"}, "_"), 0, bitlen)

	structure.aResRep = newPedersonRepresentationProofStructure(strings.Join([]string{structure.myname, "ares"}, "_"))
	structure.aPlus1ResRep = RepresentationProofStructure{
		[]LhsContribution{
			LhsContribution{strings.Join([]string{structure.myname, "ares"}, "_"), big.NewInt(1)},
			LhsContribution{"g", big.NewInt(-1)},
		},
		[]RhsContribution{
			RhsContribution{"h", strings.Join([]string{structure.myname, "aresplus1hider"}, "_"), 1},
		},
	}
	structure.aMin1ResRep = RepresentationProofStructure{
		[]LhsContribution{
			LhsContribution{strings.Join([]string{structure.myname, "ares"}, "_"), big.NewInt(1)},
			LhsContribution{"g", big.NewInt(1)},
		},
		[]RhsContribution{
			RhsContribution{"h", strings.Join([]string{structure.myname, "aresmin1hider"}, "_"), 1},
		},
	}

	structure.anegResRep = RepresentationProofStructure{
		[]LhsContribution{
			LhsContribution{strings.Join([]string{structure.myname, "anegres"}, "_"), big.NewInt(1)},
			LhsContribution{"g", big.NewInt(1)},
		},
		[]RhsContribution{
			RhsContribution{"h", strings.Join([]string{structure.myname, "anegres", "hider"}, "_"), 1},
		},
	}

	structure.aExp = newExpProofStructure(
		strings.Join([]string{structure.myname, "a"}, "_"),
		strings.Join([]string{structure.myname, "halfp"}, "_"),
		name,
		strings.Join([]string{structure.myname, "ares"}, "_"),
		bitlen)
	structure.anegExp = newExpProofStructure(
		strings.Join([]string{structure.myname, "aneg"}, "_"),
		strings.Join([]string{structure.myname, "halfp"}, "_"),
		name,
		strings.Join([]string{structure.myname, "anegres"}, "_"),
		bitlen)
	return structure
}

func (s *PrimeProofStructure) GenerateCommitmentsFromSecrets(g group, list []*big.Int, bases BaseLookup, secretdata SecretLookup) ([]*big.Int, PrimeProofCommit) {
	var commit PrimeProofCommit

	// basic setup
	commit.namePreaMod = strings.Join([]string{s.myname, "preamod"}, "_")
	commit.namePreaHider = strings.Join([]string{s.myname, "preahider"}, "_")

	// Build prea
	commit.preaPederson = newPedersonSecret(g, strings.Join([]string{s.myname, "prea"}, "_"), randomBigInt(secretdata.GetSecret(s.primeName)))

	// Calculate aAdd, a, and d
	aAdd := getHashNumber(commit.preaPederson.commit, nil, 0, s.bitlen)
	d, a := new(big.Int).DivMod(
		new(big.Int).Add(
			commit.preaPederson.secret,
			aAdd),
		secretdata.GetSecret(s.primeName),
		new(big.Int))

	// Catch rare generation error
	if a.Cmp(big.NewInt(0)) == 0 {
		panic("Generated a outside of Z*")
	}

	// Generate a related commitments
	commit.aPederson = newPedersonSecret(g, strings.Join([]string{s.myname, "a"}, "_"), a)
	commit.preaMod = d
	commit.preaModRandomizer = randomBigInt(g.order)
	commit.preaHider = new(big.Int).Mod(
		new(big.Int).Sub(
			commit.preaPederson.hider,
			new(big.Int).Add(
				commit.aPederson.hider,
				new(big.Int).Mul(
					d,
					secretdata.GetSecret(strings.Join([]string{s.primeName, "hider"}, "_"))))),
		g.order)
	commit.preaHiderRandomizer = randomBigInt(g.order)

	// Find aneg
	aneg := randomBigInt(secretdata.GetSecret(s.primeName))
	anegPow := new(big.Int).Exp(aneg, new(big.Int).Rsh(secretdata.GetSecret(s.primeName), 1), secretdata.GetSecret(s.primeName))
	for anegPow.Cmp(new(big.Int).Sub(secretdata.GetSecret(s.primeName), big.NewInt(1))) != 0 {
		aneg.Set(randomBigInt(secretdata.GetSecret(s.primeName)))
		anegPow.Exp(aneg, new(big.Int).Rsh(secretdata.GetSecret(s.primeName), 1), secretdata.GetSecret(s.primeName))
	}

	// And build its pederson commitment
	commit.anegPederson = newPedersonSecret(g, strings.Join([]string{s.myname, "aneg"}, "_"), aneg)

	// Generate result pederson commits and proof data
	aRes := new(big.Int).Exp(a, new(big.Int).Rsh(secretdata.GetSecret(s.primeName), 1), secretdata.GetSecret(s.primeName))
	if aRes.Cmp(big.NewInt(1)) != 0 {
		aRes.Sub(aRes, secretdata.GetSecret(s.primeName))
	}
	anegRes := new(big.Int).Exp(aneg, new(big.Int).Rsh(secretdata.GetSecret(s.primeName), 1), secretdata.GetSecret(s.primeName))
	anegRes.Sub(anegRes, secretdata.GetSecret(s.primeName))
	commit.aResPederson = newPedersonSecret(g, strings.Join([]string{s.myname, "ares"}, "_"), aRes)
	commit.anegResPederson = newPedersonSecret(g, strings.Join([]string{s.myname, "anegres"}, "_"), anegRes)
	commit.aInvalidResult = randomBigInt(g.order)
	commit.aInvalidChallenge = randomBigInt(new(big.Int).Lsh(big.NewInt(1), 256))
	commit.aValid = commit.aResPederson.hider
	commit.aValidRandomizer = randomBigInt(g.order)
	if aRes.Cmp(big.NewInt(1)) == 0 {
		commit.nameAValid = strings.Join([]string{s.myname, "aresplus1hider"}, "_")
		commit.nameAInvalid = strings.Join([]string{s.myname, "aresmin1hider"}, "_")
		commit.aPositive = true
	} else {
		commit.nameAValid = strings.Join([]string{s.myname, "aresmin1hider"}, "_")
		commit.nameAInvalid = strings.Join([]string{s.myname, "aresplus1hider"}, "_")
		commit.aPositive = false
	}

	// the half p pederson commit
	commit.halfPPederson = newPedersonSecret(g, strings.Join([]string{s.myname, "halfp"}, "_"), new(big.Int).Rsh(secretdata.GetSecret(s.primeName), 1))

	// Build structure for the a generation proofs
	agenproof := RepresentationProofStructure{
		[]LhsContribution{
			LhsContribution{commit.preaPederson.name, big.NewInt(1)},
			LhsContribution{"g", aAdd},
			LhsContribution{commit.aPederson.name, big.NewInt(-1)},
		},
		[]RhsContribution{
			RhsContribution{s.primeName, commit.namePreaMod, 1},
			RhsContribution{"h", commit.namePreaHider, 1},
		},
	}
	agenrange := RangeProofStructure{
		agenproof,
		commit.namePreaMod,
		0,
		s.bitlen,
	}

	// Inner secrets and bases structures
	innerBases := newBaseMerge(&commit.preaPederson, &commit.aPederson, &commit.anegPederson, &commit.aResPederson, &commit.anegResPederson, &commit.halfPPederson, bases)
	secrets := newSecretMerge(&commit, &commit.preaPederson, &commit.aPederson, &commit.anegPederson, &commit.aResPederson, &commit.anegResPederson, &commit.halfPPederson, secretdata)

	// Build all commitments
	list = commit.halfPPederson.GenerateCommitments(list)
	list = commit.preaPederson.GenerateCommitments(list)
	list = commit.aPederson.GenerateCommitments(list)
	list = commit.anegPederson.GenerateCommitments(list)
	list = commit.aResPederson.GenerateCommitments(list)
	list = commit.anegResPederson.GenerateCommitments(list)
	list = s.halfPRep.GenerateCommitmentsFromSecrets(g, list, &innerBases, &secrets)
	list = s.preaRep.GenerateCommitmentsFromSecrets(g, list, &innerBases, &secrets)
	list, commit.preaRangeCommit = s.preaRange.GenerateCommitmentsFromSecrets(g, list, &innerBases, &secrets)
	list = s.aRep.GenerateCommitmentsFromSecrets(g, list, &innerBases, &secrets)
	list, commit.aRangeCommit = s.aRange.GenerateCommitmentsFromSecrets(g, list, &innerBases, &secrets)
	list = s.anegRep.GenerateCommitmentsFromSecrets(g, list, &innerBases, &secrets)
	list, commit.anegRangeCommit = s.anegRange.GenerateCommitmentsFromSecrets(g, list, &innerBases, &secrets)
	list = agenproof.GenerateCommitmentsFromSecrets(g, list, &innerBases, &secrets)
	list, commit.preaModRangeCommit = agenrange.GenerateCommitmentsFromSecrets(g, list, &innerBases, &secrets)
	list = s.aResRep.GenerateCommitmentsFromSecrets(g, list, &innerBases, &secrets)
	list = s.anegResRep.GenerateCommitmentsFromSecrets(g, list, &innerBases, &secrets)
	if commit.aPositive {
		list = s.aPlus1ResRep.GenerateCommitmentsFromSecrets(g, list, &innerBases, &secrets)
		list = s.aMin1ResRep.GenerateCommitmentsFromProof(g, list, commit.aInvalidChallenge, &innerBases, &commit)
	} else {
		list = s.aPlus1ResRep.GenerateCommitmentsFromProof(g, list, commit.aInvalidChallenge, &innerBases, &commit)
		list = s.aMin1ResRep.GenerateCommitmentsFromSecrets(g, list, &innerBases, &secrets)
	}
	list, commit.aExpCommit = s.aExp.GenerateCommitmentsFromSecrets(g, list, &innerBases, &secrets)
	list, commit.anegExpCommit = s.anegExp.GenerateCommitmentsFromSecrets(g, list, &innerBases, &secrets)

	return list, commit
}

func (s *PrimeProofStructure) BuildProof(g group, challenge *big.Int, commit PrimeProofCommit, secretdata SecretLookup) PrimeProof {
	var proof PrimeProof

	// Rebuild structure for the a generation proofs
	aAdd := getHashNumber(commit.preaPederson.commit, nil, 0, s.bitlen)
	agenproof := RepresentationProofStructure{
		[]LhsContribution{
			LhsContribution{commit.preaPederson.name, big.NewInt(1)},
			LhsContribution{"g", aAdd},
			LhsContribution{commit.aPederson.name, big.NewInt(-1)},
		},
		[]RhsContribution{
			RhsContribution{s.primeName, commit.namePreaMod, 1},
			RhsContribution{"h", commit.namePreaHider, 1},
		},
	}
	agenrange := RangeProofStructure{
		agenproof,
		commit.namePreaMod,
		0,
		s.bitlen,
	}

	// Recreate full secrets lookup
	secrets := newSecretMerge(&commit, &commit.preaPederson, &commit.aPederson, &commit.anegPederson, secretdata)

	// Generate proofs for the pederson commitments
	proof.halfPCommit = commit.halfPPederson.BuildProof(g, challenge)
	proof.preaCommit = commit.preaPederson.BuildProof(g, challenge)
	proof.aCommit = commit.aPederson.BuildProof(g, challenge)
	proof.anegCommit = commit.anegPederson.BuildProof(g, challenge)
	proof.aResCommit = commit.aResPederson.BuildProof(g, challenge)
	proof.anegResCommit = commit.anegResPederson.BuildProof(g, challenge)

	// Generate range proofs
	proof.preaRangeProof = s.preaRange.BuildProof(g, challenge, commit.preaRangeCommit, &secrets)
	proof.aRangeProof = s.aRange.BuildProof(g, challenge, commit.aRangeCommit, &secrets)
	proof.anegRangeProof = s.anegRange.BuildProof(g, challenge, commit.anegRangeCommit, &secrets)
	proof.preaModRangeProof = agenrange.BuildProof(g, challenge, commit.preaModRangeCommit, &secrets)

	// And calculate our results
	proof.preaModResult = new(big.Int).Mod(
		new(big.Int).Sub(
			commit.preaModRandomizer,
			new(big.Int).Mul(
				challenge,
				commit.preaMod)),
		g.order)
	proof.preaHiderResult = new(big.Int).Mod(
		new(big.Int).Sub(
			commit.preaHiderRandomizer,
			new(big.Int).Mul(
				challenge,
				commit.preaHider)),
		g.order)

	if commit.aPositive {
		proof.aPlus1Challenge = new(big.Int).Xor(challenge, commit.aInvalidChallenge)
		proof.aPlus1Result = new(big.Int).Mod(
			new(big.Int).Sub(
				commit.aValidRandomizer,
				new(big.Int).Mul(
					proof.aPlus1Challenge,
					commit.aValid)),
			g.order)

		proof.aMin1Challenge = commit.aInvalidChallenge
		proof.aMin1Result = commit.aInvalidResult
	} else {
		proof.aPlus1Challenge = commit.aInvalidChallenge
		proof.aPlus1Result = commit.aInvalidResult

		proof.aMin1Challenge = new(big.Int).Xor(challenge, commit.aInvalidChallenge)
		proof.aMin1Result = new(big.Int).Mod(
			new(big.Int).Sub(
				commit.aValidRandomizer,
				new(big.Int).Mul(
					proof.aMin1Challenge,
					commit.aValid)),
			g.order)
	}

	proof.aExpProof = s.aExp.BuildProof(g, challenge, commit.aExpCommit, &secrets)
	proof.anegExpProof = s.anegExp.BuildProof(g, challenge, commit.anegExpCommit, &secrets)

	return proof
}

func (s *PrimeProofStructure) FakeProof(g group, challenge *big.Int) PrimeProof {
	var proof PrimeProof

	// Fake the pederson proofs
	proof.halfPCommit = newPedersonFakeProof(g)
	proof.preaCommit = newPedersonFakeProof(g)
	proof.aCommit = newPedersonFakeProof(g)
	proof.anegCommit = newPedersonFakeProof(g)
	proof.aResCommit = newPedersonFakeProof(g)
	proof.anegResCommit = newPedersonFakeProof(g)

	// Build the fake proof structure for the preaMod rangeproof
	aAdd := getHashNumber(proof.preaCommit.Commit, nil, 0, s.bitlen)
	agenproof := RepresentationProofStructure{
		[]LhsContribution{
			LhsContribution{strings.Join([]string{s.myname, "prea"}, "_"), big.NewInt(1)},
			LhsContribution{"g", aAdd},
			LhsContribution{strings.Join([]string{s.myname, "a"}, "_"), big.NewInt(-1)},
		},
		[]RhsContribution{
			RhsContribution{s.primeName, strings.Join([]string{s.myname, "preamod"}, "_"), 1},
			RhsContribution{"h", strings.Join([]string{s.myname, "preahider"}, "_"), 1},
		},
	}
	agenrange := RangeProofStructure{
		agenproof,
		strings.Join([]string{s.myname, "preamod"}, "_"),
		0,
		s.bitlen,
	}

	// Fake the range proofs
	proof.preaRangeProof = s.preaRange.FakeProof(g)
	proof.aRangeProof = s.aRange.FakeProof(g)
	proof.anegRangeProof = s.anegRange.FakeProof(g)
	proof.preaModRangeProof = agenrange.FakeProof(g)

	// And fake our bits
	proof.preaModResult = randomBigInt(g.order)
	proof.preaHiderResult = randomBigInt(g.order)
	proof.aPlus1Result = randomBigInt(g.order)
	proof.aMin1Result = randomBigInt(g.order)
	proof.aPlus1Challenge = randomBigInt(new(big.Int).Lsh(big.NewInt(1), 256))
	proof.aMin1Challenge = new(big.Int).Xor(challenge, proof.aPlus1Challenge)

	proof.aExpProof = s.aExp.FakeProof(g, challenge)
	proof.anegExpProof = s.anegExp.FakeProof(g, challenge)

	return proof
}

func (s *PrimeProofStructure) VerifyProofStructure(challenge *big.Int, proof PrimeProof) bool {
	// Check pederson commitments
	if !proof.halfPCommit.VerifyStructure() ||
		!proof.preaCommit.VerifyStructure() ||
		!proof.aCommit.VerifyStructure() ||
		!proof.anegCommit.VerifyStructure() ||
		!proof.aResCommit.VerifyStructure() ||
		!proof.anegResCommit.VerifyStructure() {
		return false
	}

	// Build the proof structure for the preaMod rangeproof
	aAdd := getHashNumber(proof.preaCommit.Commit, nil, 0, s.bitlen)
	agenproof := RepresentationProofStructure{
		[]LhsContribution{
			LhsContribution{strings.Join([]string{s.myname, "prea"}, "_"), big.NewInt(1)},
			LhsContribution{"g", aAdd},
			LhsContribution{strings.Join([]string{s.myname, "a"}, "_"), big.NewInt(-1)},
		},
		[]RhsContribution{
			RhsContribution{s.primeName, strings.Join([]string{s.myname, "preamod"}, "_"), 1},
			RhsContribution{"h", strings.Join([]string{s.myname, "preahider"}, "_"), 1},
		},
	}
	agenrange := RangeProofStructure{
		agenproof,
		strings.Join([]string{s.myname, "preamod"}, "_"),
		0,
		s.bitlen,
	}

	// Check the range proofs
	if !s.preaRange.VerifyProofStructure(proof.preaRangeProof) ||
		!s.aRange.VerifyProofStructure(proof.aRangeProof) ||
		!s.anegRange.VerifyProofStructure(proof.anegRangeProof) ||
		!agenrange.VerifyProofStructure(proof.preaModRangeProof) {
		return false
	}

	// Check our parts are here
	if proof.preaModResult == nil || proof.preaHiderResult == nil {
		return false
	}
	if proof.aPlus1Result == nil || proof.aMin1Result == nil {
		return false
	}
	if proof.aPlus1Challenge == nil || proof.aMin1Challenge == nil {
		return false
	}
	if new(big.Int).Xor(proof.aPlus1Challenge, proof.aMin1Challenge).Cmp(challenge) != 0 {
		return false
	}

	if !s.aExp.VerifyProofStructure(challenge, proof.aExpProof) ||
		!s.anegExp.VerifyProofStructure(challenge, proof.anegExpProof) {
		return false
	}

	return true
}

func (s *PrimeProofStructure) GenerateCommitmentsFromProof(g group, list []*big.Int, challenge *big.Int, bases BaseLookup, proofdata ProofLookup, proof PrimeProof) []*big.Int {
	// Setup
	proof.namePreaMod = strings.Join([]string{s.myname, "preamod"}, "_")
	proof.namePreaHider = strings.Join([]string{s.myname, "preahider"}, "_")
	proof.nameAplus1 = strings.Join([]string{s.myname, "aresplus1hider"}, "_")
	proof.nameAmin1 = strings.Join([]string{s.myname, "aresmin1hider"}, "_")
	proof.halfPCommit.SetName(strings.Join([]string{s.myname, "halfp"}, "_"))
	proof.preaCommit.SetName(strings.Join([]string{s.myname, "prea"}, "_"))
	proof.aCommit.SetName(strings.Join([]string{s.myname, "a"}, "_"))
	proof.anegCommit.SetName(strings.Join([]string{s.myname, "aneg"}, "_"))
	proof.aResCommit.SetName(strings.Join([]string{s.myname, "ares"}, "_"))
	proof.anegResCommit.SetName(strings.Join([]string{s.myname, "anegres"}, "_"))

	// Build the proof structure for the preamod proofs
	aAdd := getHashNumber(proof.preaCommit.Commit, nil, 0, s.bitlen)
	agenproof := RepresentationProofStructure{
		[]LhsContribution{
			LhsContribution{strings.Join([]string{s.myname, "prea"}, "_"), big.NewInt(1)},
			LhsContribution{"g", aAdd},
			LhsContribution{strings.Join([]string{s.myname, "a"}, "_"), big.NewInt(-1)},
		},
		[]RhsContribution{
			RhsContribution{s.primeName, strings.Join([]string{s.myname, "preamod"}, "_"), 1},
			RhsContribution{"h", strings.Join([]string{s.myname, "preahider"}, "_"), 1},
		},
	}
	agenrange := RangeProofStructure{
		agenproof,
		strings.Join([]string{s.myname, "preamod"}, "_"),
		0,
		s.bitlen,
	}

	// inner bases
	innerBases := newBaseMerge(&proof.preaCommit, &proof.aCommit, &proof.anegCommit, &proof.aResCommit, &proof.anegResCommit, &proof.halfPCommit, bases)
	proofs := newProofMerge(&proof, &proof.preaCommit, &proof.aCommit, &proof.anegCommit, &proof.aResCommit, &proof.anegResCommit, &proof.halfPCommit, proofdata)

	// Build all commitments
	list = proof.halfPCommit.GenerateCommitments(list)
	list = proof.preaCommit.GenerateCommitments(list)
	list = proof.aCommit.GenerateCommitments(list)
	list = proof.anegCommit.GenerateCommitments(list)
	list = proof.aResCommit.GenerateCommitments(list)
	list = proof.anegResCommit.GenerateCommitments(list)
	list = s.halfPRep.GenerateCommitmentsFromProof(g, list, challenge, &innerBases, &proofs)
	list = s.preaRep.GenerateCommitmentsFromProof(g, list, challenge, &innerBases, &proofs)
	list = s.preaRange.GenerateCommitmentsFromProof(g, list, challenge, &innerBases, proof.preaRangeProof)
	list = s.aRep.GenerateCommitmentsFromProof(g, list, challenge, &innerBases, &proofs)
	list = s.aRange.GenerateCommitmentsFromProof(g, list, challenge, &innerBases, proof.aRangeProof)
	list = s.anegRep.GenerateCommitmentsFromProof(g, list, challenge, &innerBases, &proofs)
	list = s.anegRange.GenerateCommitmentsFromProof(g, list, challenge, &innerBases, proof.anegRangeProof)
	list = agenproof.GenerateCommitmentsFromProof(g, list, challenge, &innerBases, &proofs)
	list = agenrange.GenerateCommitmentsFromProof(g, list, challenge, &innerBases, proof.preaModRangeProof)
	list = s.aResRep.GenerateCommitmentsFromProof(g, list, challenge, &innerBases, &proofs)
	list = s.anegResRep.GenerateCommitmentsFromProof(g, list, challenge, &innerBases, &proofs)
	list = s.aPlus1ResRep.GenerateCommitmentsFromProof(g, list, proof.aPlus1Challenge, &innerBases, &proofs)
	list = s.aMin1ResRep.GenerateCommitmentsFromProof(g, list, proof.aMin1Challenge, &innerBases, &proofs)
	list = s.aExp.GenerateCommitmentsFromProof(g, list, challenge, &innerBases, &proofs, proof.aExpProof)
	list = s.anegExp.GenerateCommitmentsFromProof(g, list, challenge, &innerBases, &proofs, proof.anegExpProof)

	return list
}

func (s *PrimeProofStructure) IsTrue(secretdata SecretLookup) bool {
	return secretdata.GetSecret(s.primeName).ProbablyPrime(40)
}
