package qspp

import "github.com/privacybydesign/gabi/big"

type QuasiSafePrimeProductCommit struct {
	asppCommit AlmostSafePrimeProductCommit
}

type QuasiSafePrimeProductProof struct {
	SFproof   SquareFreeProof
	PPPproof  PrimePowerProductProof
	DPPproof  DisjointPrimeProductProof
	ASPPproof AlmostSafePrimeProductProof
}

func QuasiSafePrimeProductBuildCommitments(list []*big.Int, Pprime *big.Int, Qprime *big.Int) ([]*big.Int, QuasiSafePrimeProductCommit) {
	var commit QuasiSafePrimeProductCommit
	list, commit.asppCommit = AlmostSafePrimeProductBuildCommitments(list, Pprime, Qprime)
	return list, commit
}

func QuasiSafePrimeProductBuildProof(Pprime *big.Int, Qprime *big.Int, challenge *big.Int, commit QuasiSafePrimeProductCommit) QuasiSafePrimeProductProof {
	// Calculate useful intermediaries
	P := new(big.Int).Add(new(big.Int).Lsh(Pprime, 1), big.NewInt(1))
	Q := new(big.Int).Add(new(big.Int).Lsh(Qprime, 1), big.NewInt(1))
	N := new(big.Int).Mul(P, Q)
	phiN := new(big.Int).Lsh(new(big.Int).Mul(Pprime, Qprime), 2)

	// Build the actual proofs
	var proof QuasiSafePrimeProductProof
	proof.SFproof = SquareFreeBuildProof(N, phiN, challenge, big.NewInt(0))
	proof.PPPproof = PrimePowerProductBuildProof(P, Q, challenge, big.NewInt(1))
	proof.DPPproof = DisjointPrimeProductBuildProof(P, Q, challenge, big.NewInt(2))
	proof.ASPPproof = AlmostSafePrimeProductBuildProof(Pprime, Qprime, challenge, big.NewInt(3), commit.asppCommit)

	return proof
}

func QuasiSafePrimeProductVerifyStructure(proof QuasiSafePrimeProductProof) bool {
	return SquareFreeVerifyStructure(proof.SFproof) &&
		PrimePowerProductVerifyStructure(proof.PPPproof) &&
		DisjointPrimeProductVerifyStructure(proof.DPPproof) &&
		AlmostSafePrimeProductVerifyStructure(proof.ASPPproof)
}

func QuasiSafePrimeProductExtractCommitments(list []*big.Int, proof QuasiSafePrimeProductProof) []*big.Int {
	return AlmostSafePrimeProductExtractCommitments(list, proof.ASPPproof)
}

func QuasiSafePrimeProductVerifyProof(N *big.Int, challenge *big.Int, proof QuasiSafePrimeProductProof) bool {
	// Check N = 5 (mod 8), as this is what differentiates quasi and almost safe prime products
	if new(big.Int).Mod(N, big.NewInt(8)).Cmp(big.NewInt(5)) != 0 {
		return false
	}

	// Verify Minimum factor rule
	for i := 2; i < minimumFactor; i++ {
		check := new(big.Int).GCD(nil, nil, N, big.NewInt(int64(i)))
		if check.Cmp(big.NewInt(1)) != 0 {
			return false
		}
	}

	// Validate the individual parts
	return SquareFreeVerifyProof(N, challenge, big.NewInt(0), proof.SFproof) &&
		PrimePowerProductVerifyProof(N, challenge, big.NewInt(1), proof.PPPproof) &&
		DisjointPrimeProductVerifyProof(N, challenge, big.NewInt(2), proof.DPPproof) &&
		AlmostSafePrimeProductVerifyProof(N, challenge, big.NewInt(3), proof.ASPPproof)
}
