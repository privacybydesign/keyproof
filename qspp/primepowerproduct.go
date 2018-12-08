package qspp

import "github.com/mhe/gabi/big"

type PrimePowerProductProof struct {
	Responses []*big.Int
}

func PrimePowerProductBuildProof(P *big.Int, Q *big.Int, challenge *big.Int, index *big.Int) PrimePowerProductProof {
	N := new(big.Int).Mul(P, Q)

	// And for response generation
	factors := []*big.Int{
		P,
		Q,
	}

	// Generate the challenges and responses
	var proof PrimePowerProductProof
	proof.Responses = []*big.Int{}
	for i := 0; i < primePowerProductIters; i++ {
		// Generate the challenge
		curc := getHashNumber(challenge, index, i, N.BitLen())
		curc.Mod(curc, N)

		if new(big.Int).GCD(nil, nil, curc, N).Cmp(big.NewInt(1)) != 0 {
			panic("Generated number not in Z_N")
		}

		r1, ok1 := modSqrt(curc, factors)
		r2, ok2 := modSqrt(new(big.Int).Mod(new(big.Int).Neg(curc), N), factors)
		r3, ok3 := modSqrt(new(big.Int).Mod(new(big.Int).Lsh(curc, 1), N), factors)
		r4, ok4 := modSqrt(new(big.Int).Mod(new(big.Int).Lsh(new(big.Int).Mod(new(big.Int).Neg(curc), N), 1), N), factors)

		if ok1 {
			proof.Responses = append(proof.Responses, r1)
		} else if ok2 {
			proof.Responses = append(proof.Responses, r2)
		} else if ok3 {
			proof.Responses = append(proof.Responses, r3)
		} else if ok4 {
			proof.Responses = append(proof.Responses, r4)
		} else {
			panic("None of +-x, +-2x are square!")
		}
	}

	return proof
}

func PrimePowerProductVerifyProof(N *big.Int, challenge *big.Int, index *big.Int, proof PrimePowerProductProof) bool {
	// Verify proof structure
	if len(proof.Responses) != primePowerProductIters {
		return false
	}

	// Generate the challenges and responses
	for i := 0; i < primePowerProductIters; i++ {
		// Generate the challenge
		curc := getHashNumber(challenge, index, i, N.BitLen())
		curc.Mod(curc, N)

		// Process response
		result := new(big.Int).Exp(proof.Responses[i], big.NewInt(2), N)

		ok1 := (result.Cmp(curc) == 0)
		ok2 := (result.Cmp(new(big.Int).Mod(new(big.Int).Neg(curc), N)) == 0)
		ok3 := (result.Cmp(new(big.Int).Mod(new(big.Int).Lsh(curc, 1), N)) == 0)
		ok4 := (result.Cmp(new(big.Int).Mod(new(big.Int).Neg(new(big.Int).Lsh(curc, 1)), N)) == 0)

		if !ok1 && !ok2 && !ok3 && !ok4 {
			return false
		}
	}

	return true
}
