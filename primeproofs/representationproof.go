package primeproofs

import "github.com/privacybydesign/gabi/big"

type LhsContribution struct {
	Base  string
	Power *big.Int
}

type RhsContribution struct {
	Base   string
	Secret string
	Power  int64
}

type RepresentationProofStructure struct {
	Lhs []LhsContribution
	Rhs []RhsContribution
}

func (s *RepresentationProofStructure) NumRangeProofs() int {
	return 0
}

func (s *RepresentationProofStructure) NumCommitments() int {
	return 1
}

func (s *RepresentationProofStructure) GenerateCommitmentsFromSecrets(g group, list []*big.Int, bases BaseLookup, secretdata SecretLookup) []*big.Int {
	commitment := big.NewInt(1)

	for _, curRhs := range s.Rhs {
		// base := bases.Exp(curRhs.Base, big.NewInt(curRhs.Power), g.P)
		// contribution := new(big.Int).Exp(base, secretdata.GetRandomizer(curRhs.Secret), g.P)
		var exp big.Int
		exp.Set(big.NewInt(curRhs.Power))
		exp.Mul(&exp, secretdata.GetRandomizer(curRhs.Secret))
		exp.Mod(&exp, g.order)
		contribution := bases.Exp(curRhs.Base, &exp, g.P)
		commitment.Mod(new(big.Int).Mul(commitment, contribution), g.P)
	}

	return append(list, commitment)
}

func (s *RepresentationProofStructure) GenerateCommitmentsFromProof(g group, list []*big.Int, challenge *big.Int, bases BaseLookup, proofdata ProofLookup) []*big.Int {
	lhs := big.NewInt(1)
	for _, curLhs := range s.Lhs {
		base := bases.Exp(curLhs.Base, curLhs.Power, g.P)
		lhs.Mod(new(big.Int).Mul(lhs, base), g.P)
	}

	commitment := new(big.Int).Exp(lhs, challenge, g.P)
	for _, curRhs := range s.Rhs {
		// base := bases.Exp(curRhs.Base, big.NewInt(curRhs.Power), g.P)
		// contribution := new(big.Int).Exp(base, proofdata.GetResult(curRhs.Secret), g.P)
		var exp big.Int
		exp.Mul(big.NewInt(curRhs.Power), proofdata.GetResult(curRhs.Secret))
		exp.Mod(&exp, g.order)
		contribution := bases.Exp(curRhs.Base, &exp, g.P)
		commitment.Mod(new(big.Int).Mul(commitment, contribution), g.P)
	}

	return append(list, commitment)
}

func (s *RepresentationProofStructure) IsTrue(g group, bases BaseLookup, secretdata SecretLookup) bool {
	lhs := big.NewInt(1)
	for _, curLhs := range s.Lhs {
		base := bases.Exp(curLhs.Base, curLhs.Power, g.P)
		lhs.Mod(new(big.Int).Mul(lhs, base), g.P)
	}

	rhs := big.NewInt(1)
	for _, curRhs := range s.Rhs {
		base := bases.Exp(curRhs.Base, big.NewInt(curRhs.Power), g.P)
		contribution := new(big.Int).Exp(base, secretdata.GetSecret(curRhs.Secret), g.P)
		rhs.Mod(new(big.Int).Mul(rhs, contribution), g.P)
	}

	return lhs.Cmp(rhs) == 0
}
