package primeproofs

import "github.com/privacybydesign/keyproof/common"
import "github.com/privacybydesign/gabi/big"
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

	HalfPCommit   PedersonProof
	PreaCommit    PedersonProof
	ACommit       PedersonProof
	AnegCommit    PedersonProof
	AResCommit    PedersonProof
	AnegResCommit PedersonProof

	PreaModResult   *big.Int
	PreaHiderResult *big.Int

	APlus1Result    *big.Int
	AMin1Result     *big.Int
	APlus1Challenge *big.Int
	AMin1Challenge  *big.Int

	PreaRangeProof    RangeProof
	ARangeProof       RangeProof
	AnegRangeProof    RangeProof
	PreaModRangeProof RangeProof

	AExpProof    expProof
	AnegExpProof expProof
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
		return p.PreaModResult
	}
	if name == p.namePreaHider {
		return p.PreaHiderResult
	}
	if name == p.nameAplus1 {
		return p.APlus1Result
	}
	if name == p.nameAmin1 {
		return p.AMin1Result
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

func (s *PrimeProofStructure) NumRangeProofs() int {
	res := 4
	res += s.aExp.NumRangeProofs()
	res += s.anegExp.NumRangeProofs()
	return res
}

func (s *PrimeProofStructure) NumCommitments() int {
	res := 6
	res += s.halfPRep.NumCommitments()
	res += s.preaRep.NumCommitments()
	res += s.preaRange.NumCommitments()
	res += s.aRep.NumCommitments()
	res += s.aRange.NumCommitments()
	res += s.anegRep.NumCommitments()
	res += s.anegRange.NumCommitments()
	res += 1
	res += rangeProofIters
	res += s.aResRep.NumCommitments()
	res += s.anegResRep.NumCommitments()
	res += s.aPlus1ResRep.NumCommitments()
	res += s.aMin1ResRep.NumCommitments()
	res += s.aExp.NumCommitments()
	res += s.anegExp.NumCommitments()
	return res
}

func (s *PrimeProofStructure) GenerateCommitmentsFromSecrets(g group, list []*big.Int, bases BaseLookup, secretdata SecretLookup) ([]*big.Int, PrimeProofCommit) {
	var commit PrimeProofCommit

	// basic setup
	commit.namePreaMod = strings.Join([]string{s.myname, "preamod"}, "_")
	commit.namePreaHider = strings.Join([]string{s.myname, "preahider"}, "_")

	// Build prea
	commit.preaPederson = newPedersonSecret(g, strings.Join([]string{s.myname, "prea"}, "_"), common.RandomBigInt(secretdata.GetSecret(s.primeName)))

	// Calculate aAdd, a, and d
	aAdd := common.GetHashNumber(commit.preaPederson.commit, nil, 0, s.bitlen)
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
	commit.preaModRandomizer = common.RandomBigInt(g.order)
	commit.preaHider = new(big.Int).Mod(
		new(big.Int).Sub(
			commit.preaPederson.hider,
			new(big.Int).Add(
				commit.aPederson.hider,
				new(big.Int).Mul(
					d,
					secretdata.GetSecret(strings.Join([]string{s.primeName, "hider"}, "_"))))),
		g.order)
	commit.preaHiderRandomizer = common.RandomBigInt(g.order)

	// Find aneg
	aneg := common.RandomBigInt(secretdata.GetSecret(s.primeName))
	anegPow := new(big.Int).Exp(aneg, new(big.Int).Rsh(secretdata.GetSecret(s.primeName), 1), secretdata.GetSecret(s.primeName))
	for anegPow.Cmp(new(big.Int).Sub(secretdata.GetSecret(s.primeName), big.NewInt(1))) != 0 {
		aneg.Set(common.RandomBigInt(secretdata.GetSecret(s.primeName)))
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
	commit.aInvalidResult = common.RandomBigInt(g.order)
	commit.aInvalidChallenge = common.RandomBigInt(new(big.Int).Lsh(big.NewInt(1), 256))
	commit.aValid = commit.aResPederson.hider
	commit.aValidRandomizer = common.RandomBigInt(g.order)
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
	aAdd := common.GetHashNumber(commit.preaPederson.commit, nil, 0, s.bitlen)
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
	proof.HalfPCommit = commit.halfPPederson.BuildProof(g, challenge)
	proof.PreaCommit = commit.preaPederson.BuildProof(g, challenge)
	proof.ACommit = commit.aPederson.BuildProof(g, challenge)
	proof.AnegCommit = commit.anegPederson.BuildProof(g, challenge)
	proof.AResCommit = commit.aResPederson.BuildProof(g, challenge)
	proof.AnegResCommit = commit.anegResPederson.BuildProof(g, challenge)

	// Generate range proofs
	proof.PreaRangeProof = s.preaRange.BuildProof(g, challenge, commit.preaRangeCommit, &secrets)
	proof.ARangeProof = s.aRange.BuildProof(g, challenge, commit.aRangeCommit, &secrets)
	proof.AnegRangeProof = s.anegRange.BuildProof(g, challenge, commit.anegRangeCommit, &secrets)
	proof.PreaModRangeProof = agenrange.BuildProof(g, challenge, commit.preaModRangeCommit, &secrets)

	// And calculate our results
	proof.PreaModResult = new(big.Int).Mod(
		new(big.Int).Sub(
			commit.preaModRandomizer,
			new(big.Int).Mul(
				challenge,
				commit.preaMod)),
		g.order)
	proof.PreaHiderResult = new(big.Int).Mod(
		new(big.Int).Sub(
			commit.preaHiderRandomizer,
			new(big.Int).Mul(
				challenge,
				commit.preaHider)),
		g.order)

	if commit.aPositive {
		proof.APlus1Challenge = new(big.Int).Xor(challenge, commit.aInvalidChallenge)
		proof.APlus1Result = new(big.Int).Mod(
			new(big.Int).Sub(
				commit.aValidRandomizer,
				new(big.Int).Mul(
					proof.APlus1Challenge,
					commit.aValid)),
			g.order)

		proof.AMin1Challenge = commit.aInvalidChallenge
		proof.AMin1Result = commit.aInvalidResult
	} else {
		proof.APlus1Challenge = commit.aInvalidChallenge
		proof.APlus1Result = commit.aInvalidResult

		proof.AMin1Challenge = new(big.Int).Xor(challenge, commit.aInvalidChallenge)
		proof.AMin1Result = new(big.Int).Mod(
			new(big.Int).Sub(
				commit.aValidRandomizer,
				new(big.Int).Mul(
					proof.AMin1Challenge,
					commit.aValid)),
			g.order)
	}

	proof.AExpProof = s.aExp.BuildProof(g, challenge, commit.aExpCommit, &secrets)
	proof.AnegExpProof = s.anegExp.BuildProof(g, challenge, commit.anegExpCommit, &secrets)

	return proof
}

func (s *PrimeProofStructure) FakeProof(g group, challenge *big.Int) PrimeProof {
	var proof PrimeProof

	// Fake the pederson proofs
	proof.HalfPCommit = newPedersonFakeProof(g)
	proof.PreaCommit = newPedersonFakeProof(g)
	proof.ACommit = newPedersonFakeProof(g)
	proof.AnegCommit = newPedersonFakeProof(g)
	proof.AResCommit = newPedersonFakeProof(g)
	proof.AnegResCommit = newPedersonFakeProof(g)

	// Build the fake proof structure for the preaMod rangeproof
	aAdd := common.GetHashNumber(proof.PreaCommit.Commit, nil, 0, s.bitlen)
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
	proof.PreaRangeProof = s.preaRange.FakeProof(g)
	proof.ARangeProof = s.aRange.FakeProof(g)
	proof.AnegRangeProof = s.anegRange.FakeProof(g)
	proof.PreaModRangeProof = agenrange.FakeProof(g)

	// And fake our bits
	proof.PreaModResult = common.RandomBigInt(g.order)
	proof.PreaHiderResult = common.RandomBigInt(g.order)
	proof.APlus1Result = common.RandomBigInt(g.order)
	proof.AMin1Result = common.RandomBigInt(g.order)
	proof.APlus1Challenge = common.RandomBigInt(new(big.Int).Lsh(big.NewInt(1), 256))
	proof.AMin1Challenge = new(big.Int).Xor(challenge, proof.APlus1Challenge)

	proof.AExpProof = s.aExp.FakeProof(g, challenge)
	proof.AnegExpProof = s.anegExp.FakeProof(g, challenge)

	return proof
}

func (s *PrimeProofStructure) VerifyProofStructure(challenge *big.Int, proof PrimeProof) bool {
	// Check pederson commitments
	if !proof.HalfPCommit.VerifyStructure() ||
		!proof.PreaCommit.VerifyStructure() ||
		!proof.ACommit.VerifyStructure() ||
		!proof.AnegCommit.VerifyStructure() ||
		!proof.AResCommit.VerifyStructure() ||
		!proof.AnegResCommit.VerifyStructure() {
		return false
	}

	// Build the proof structure for the preaMod rangeproof
	aAdd := common.GetHashNumber(proof.PreaCommit.Commit, nil, 0, s.bitlen)
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
	if !s.preaRange.VerifyProofStructure(proof.PreaRangeProof) ||
		!s.aRange.VerifyProofStructure(proof.ARangeProof) ||
		!s.anegRange.VerifyProofStructure(proof.AnegRangeProof) ||
		!agenrange.VerifyProofStructure(proof.PreaModRangeProof) {
		return false
	}

	// Check our parts are here
	if proof.PreaModResult == nil || proof.PreaHiderResult == nil {
		return false
	}
	if proof.APlus1Result == nil || proof.AMin1Result == nil {
		return false
	}
	if proof.APlus1Challenge == nil || proof.AMin1Challenge == nil {
		return false
	}
	if new(big.Int).Xor(proof.APlus1Challenge, proof.AMin1Challenge).Cmp(challenge) != 0 {
		return false
	}

	if !s.aExp.VerifyProofStructure(challenge, proof.AExpProof) ||
		!s.anegExp.VerifyProofStructure(challenge, proof.AnegExpProof) {
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
	proof.HalfPCommit.SetName(strings.Join([]string{s.myname, "halfp"}, "_"))
	proof.PreaCommit.SetName(strings.Join([]string{s.myname, "prea"}, "_"))
	proof.ACommit.SetName(strings.Join([]string{s.myname, "a"}, "_"))
	proof.AnegCommit.SetName(strings.Join([]string{s.myname, "aneg"}, "_"))
	proof.AResCommit.SetName(strings.Join([]string{s.myname, "ares"}, "_"))
	proof.AnegResCommit.SetName(strings.Join([]string{s.myname, "anegres"}, "_"))

	// Build the proof structure for the preamod proofs
	aAdd := common.GetHashNumber(proof.PreaCommit.Commit, nil, 0, s.bitlen)
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
	innerBases := newBaseMerge(&proof.PreaCommit, &proof.ACommit, &proof.AnegCommit, &proof.AResCommit, &proof.AnegResCommit, &proof.HalfPCommit, bases)
	proofs := newProofMerge(&proof, &proof.PreaCommit, &proof.ACommit, &proof.AnegCommit, &proof.AResCommit, &proof.AnegResCommit, &proof.HalfPCommit, proofdata)

	// Build all commitments
	list = proof.HalfPCommit.GenerateCommitments(list)
	list = proof.PreaCommit.GenerateCommitments(list)
	list = proof.ACommit.GenerateCommitments(list)
	list = proof.AnegCommit.GenerateCommitments(list)
	list = proof.AResCommit.GenerateCommitments(list)
	list = proof.AnegResCommit.GenerateCommitments(list)
	list = s.halfPRep.GenerateCommitmentsFromProof(g, list, challenge, &innerBases, &proofs)
	list = s.preaRep.GenerateCommitmentsFromProof(g, list, challenge, &innerBases, &proofs)
	list = s.preaRange.GenerateCommitmentsFromProof(g, list, challenge, &innerBases, proof.PreaRangeProof)
	list = s.aRep.GenerateCommitmentsFromProof(g, list, challenge, &innerBases, &proofs)
	list = s.aRange.GenerateCommitmentsFromProof(g, list, challenge, &innerBases, proof.ARangeProof)
	list = s.anegRep.GenerateCommitmentsFromProof(g, list, challenge, &innerBases, &proofs)
	list = s.anegRange.GenerateCommitmentsFromProof(g, list, challenge, &innerBases, proof.AnegRangeProof)
	list = agenproof.GenerateCommitmentsFromProof(g, list, challenge, &innerBases, &proofs)
	list = agenrange.GenerateCommitmentsFromProof(g, list, challenge, &innerBases, proof.PreaModRangeProof)
	list = s.aResRep.GenerateCommitmentsFromProof(g, list, challenge, &innerBases, &proofs)
	list = s.anegResRep.GenerateCommitmentsFromProof(g, list, challenge, &innerBases, &proofs)
	list = s.aPlus1ResRep.GenerateCommitmentsFromProof(g, list, proof.APlus1Challenge, &innerBases, &proofs)
	list = s.aMin1ResRep.GenerateCommitmentsFromProof(g, list, proof.AMin1Challenge, &innerBases, &proofs)
	list = s.aExp.GenerateCommitmentsFromProof(g, list, challenge, &innerBases, &proofs, proof.AExpProof)
	list = s.anegExp.GenerateCommitmentsFromProof(g, list, challenge, &innerBases, &proofs, proof.AnegExpProof)

	return list
}

func (s *PrimeProofStructure) IsTrue(secretdata SecretLookup) bool {
	return secretdata.GetSecret(s.primeName).ProbablyPrime(40)
}
