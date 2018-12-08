package qspp

import "github.com/mhe/gabi/big"

type SquareFreeProof struct {
	Responses []*big.Int
}

func SquareFreeBuildProof(N *big.Int, phiN *big.Int, challenge *big.Int, index *big.Int) SquareFreeProof {
	// Precalculate the primary part of the response
	M := new(big.Int).ModInverse(N, phiN)
	if M == nil {
		panic("Trying to create SquareFree proof that doesn't hold")
	}

	// Generate the challenges and responses
	var proof SquareFreeProof
	proof.Responses = []*big.Int{}
	for i := 0; i < squareFreeIters; i++ {
		// Generate the challenge
		curc := getHashNumber(challenge, index, i, N.BitLen())
		curc.Mod(curc, N)

		if new(big.Int).GCD(nil, nil, curc, N).Cmp(big.NewInt(1)) != 0 {
			panic("Generated number not in Z_N")
		}

		// Generate response
		proof.Responses = append(proof.Responses, new(big.Int).Exp(curc, M, N))
	}

	return proof
}

func SquareFreeVerifyProof(N *big.Int, challenge *big.Int, index *big.Int, proof SquareFreeProof) bool {
	// Verify proof structure
	if len(proof.Responses) != squareFreeIters {
		return false
	}

	// Generate the challenges and verify responses
	for i := 0; i < squareFreeIters; i++ {
		// Generate the challenge
		curc := getHashNumber(challenge, index, i, N.BitLen())
		curc.Mod(curc, N)

		responseResult := new(big.Int).Exp(proof.Responses[i], N, N)
		if responseResult.Cmp(curc) != 0 {
			return false
		}
	}

	return true
}
