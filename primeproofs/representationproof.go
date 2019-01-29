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
	var exp, contribution big.Int

	for _, curRhs := range s.Rhs {
		// base := bases.Exp(curRhs.Base, big.NewInt(curRhs.Power), g.P)
		// contribution := new(big.Int).Exp(base, secretdata.GetRandomizer(curRhs.Secret), g.P)
		exp.Set(big.NewInt(curRhs.Power))
		exp.Mul(&exp, secretdata.GetRandomizer(curRhs.Secret))
		g.orderMod.Mod(&exp, &exp)
		bases.Exp(&contribution, curRhs.Base, &exp, g.P)
		commitment.Mul(commitment, &contribution)
		g.PMod.Mod(commitment, commitment)
	}

	return append(list, commitment)
}

func (s *RepresentationProofStructure) GenerateCommitmentsFromProof(g group, list []*big.Int, challenge *big.Int, bases BaseLookup, proofdata ProofLookup) []*big.Int {
	var base, tmp, lhs big.Int
	lhs.SetUint64(1)
	for _, curLhs := range s.Lhs {
		bases.Exp(&base, curLhs.Base, curLhs.Power, g.P)
		tmp.Mul(&lhs, &base)
		g.PMod.Mod(&lhs, &tmp)
	}

	commitment := new(big.Int).Exp(&lhs, challenge, g.P)
	var exp, contribution big.Int
	for _, curRhs := range s.Rhs {
		// base := bases.Exp(curRhs.Base, big.NewInt(curRhs.Power), g.P)
		// contribution := new(big.Int).Exp(base, proofdata.GetResult(curRhs.Secret), g.P)
		exp.Mul(big.NewInt(curRhs.Power), proofdata.GetResult(curRhs.Secret))
		g.orderMod.Mod(&exp, &exp)
		bases.Exp(&contribution, curRhs.Base, &exp, g.P)
		commitment.Mul(commitment, &contribution)
		g.PMod.Mod(commitment, commitment)
	}

	return append(list, commitment)
}

func (s *RepresentationProofStructure) IsTrue(g group, bases BaseLookup, secretdata SecretLookup) bool {
	var base, tmp, lhs, rhs big.Int
	lhs.SetUint64(1)
	for _, curLhs := range s.Lhs {
		bases.Exp(&base, curLhs.Base, curLhs.Power, g.P)
		tmp.Mul(&lhs, &base)
		g.PMod.Mod(&lhs, &tmp)
	}

	rhs.SetUint64(1)
	var exp, contribution big.Int
	for _, curRhs := range s.Rhs {
		exp.SetInt64(curRhs.Power)
		tmp.Mul(&exp, secretdata.GetSecret(curRhs.Secret))
		g.orderMod.Mod(&exp, &tmp)
		bases.Exp(&contribution, curRhs.Base, &exp, g.P)
		tmp.Mul(&rhs, &contribution)
		g.PMod.Mod(&rhs, &tmp)
	}

	return lhs.Cmp(&rhs) == 0
}
