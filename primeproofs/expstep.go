package primeproofs

import "github.com/mhe/gabi/big"

type expStepStructure struct {
	bitname string
	stepa   expStepAStructure
	stepb   expStepBStructure
}

type expStepCommit struct {
	isTypeA bool

	Acommit    expStepACommit
	Aproof     expStepAProof
	Achallenge *big.Int

	Bcommit    expStepBCommit
	Bproof     expStepBProof
	Bchallenge *big.Int
}

type expStepProof struct {
	Achallenge *big.Int
	Aproof     expStepAProof

	Bchallenge *big.Int
	Bproof     expStepBProof
}

func newExpStepStructure(bitname, prename, postname, mulname, modname string, bitlen uint) expStepStructure {
	var structure expStepStructure
	structure.bitname = bitname
	structure.stepa = newExpStepAStructure(bitname, prename, postname)
	structure.stepb = newExpStepBStructure(bitname, prename, postname, mulname, modname, bitlen)
	return structure
}

func (s *expStepStructure) GenerateCommitmentsFromSecrets(g group, list []*big.Int, bases BaseLookup, secretdata SecretLookup) ([]*big.Int, expStepCommit) {
	var commit expStepCommit

	if secretdata.GetSecret(s.bitname).Cmp(big.NewInt(0)) == 0 {
		commit.isTypeA = true

		// prove a
		list, commit.Acommit = s.stepa.GenerateCommitmentsFromSecrets(g, list, bases, secretdata)

		// fake b
		commit.Bchallenge = randomBigInt(new(big.Int).Lsh(big.NewInt(1), 256))
		commit.Bproof = s.stepb.FakeProof(g)
		list = s.stepb.GenerateCommitmentsFromProof(g, list, commit.Bchallenge, bases, commit.Bproof)
	} else {
		commit.isTypeA = false

		// fake a
		commit.Achallenge = randomBigInt(new(big.Int).Lsh(big.NewInt(1), 256))
		commit.Aproof = s.stepa.FakeProof(g)
		list = s.stepa.GenerateCommitmentsFromProof(g, list, commit.Achallenge, bases, commit.Aproof)

		// prove b
		list, commit.Bcommit = s.stepb.GenerateCommitmentsFromSecrets(g, list, bases, secretdata)
	}

	return list, commit
}

func (s *expStepStructure) BuildProof(g group, challenge *big.Int, commit expStepCommit, secretdata SecretLookup) expStepProof {
	var proof expStepProof

	if commit.isTypeA {
		// Build a proof
		proof.Achallenge = new(big.Int).Xor(challenge, commit.Bchallenge)
		proof.Aproof = s.stepa.BuildProof(g, proof.Achallenge, commit.Acommit, secretdata)

		// Copy b proof
		proof.Bchallenge = commit.Bchallenge
		proof.Bproof = commit.Bproof
	} else {
		// Copy a proof
		proof.Achallenge = commit.Achallenge
		proof.Aproof = commit.Aproof

		// Build b proof
		proof.Bchallenge = new(big.Int).Xor(challenge, commit.Achallenge)
		proof.Bproof = s.stepb.BuildProof(g, proof.Bchallenge, commit.Bcommit, secretdata)
	}

	return proof
}

func (s *expStepStructure) FakeProof(g group, challenge *big.Int) expStepProof {
	var proof expStepProof

	proof.Achallenge = randomBigInt(new(big.Int).Lsh(big.NewInt(1), 256))
	proof.Bchallenge = new(big.Int).Xor(challenge, proof.Achallenge)
	proof.Aproof = s.stepa.FakeProof(g)
	proof.Bproof = s.stepb.FakeProof(g)

	return proof
}

func (s *expStepStructure) VerifyProofStructure(challenge *big.Int, proof expStepProof) bool {
	if proof.Achallenge == nil || proof.Bchallenge == nil {
		return false
	}

	if challenge.Cmp(new(big.Int).Xor(proof.Achallenge, proof.Bchallenge)) != 0 {
		return false
	}

	return s.stepa.VerifyProofStructure(proof.Aproof) && s.stepb.VerifyProofStructure(proof.Bproof)
}

func (s *expStepStructure) GenerateCommitmentsFromProof(g group, list []*big.Int, challenge *big.Int, bases BaseLookup, proof expStepProof) []*big.Int {
	list = s.stepa.GenerateCommitmentsFromProof(g, list, proof.Achallenge, bases, proof.Aproof)
	list = s.stepb.GenerateCommitmentsFromProof(g, list, proof.Bchallenge, bases, proof.Bproof)
	return list
}

func (s *expStepStructure) IsTrue(secretdata SecretLookup) bool {
	return s.stepa.IsTrue(secretdata) || s.stepb.IsTrue(secretdata)
}
