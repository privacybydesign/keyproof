package primeproofs

import "github.com/privacybydesign/keyproof/common"
import "github.com/mhe/gabi/big"

type RangeProofStructure struct {
	RepresentationProofStructure
	rangeSecret string
	l1          uint
	l2          uint
}

type RangeProof struct {
	Results map[string][]*big.Int
}

type RangeCommit struct {
	commits map[string][]*big.Int
}

type RangeCommitSecretLookup struct {
	RangeCommit
	i int
}

func (r *RangeCommitSecretLookup) GetSecret(name string) *big.Int {
	return nil
}

func (r *RangeCommitSecretLookup) GetRandomizer(name string) *big.Int {
	clist, ok := r.commits[name]
	if !ok {
		return nil
	}
	return clist[r.i]
}

var RangeProofLog func() = func() {}

func (s *RangeProofStructure) NumRangeProofs() int {
	return 1
}

func (s *RangeProofStructure) GenerateCommitmentsFromSecrets(g group, list []*big.Int, bases BaseLookup, secretdata SecretLookup) ([]*big.Int, RangeCommit) {
	var commit RangeCommitSecretLookup

	// Build up commit datastructure
	commit.commits = map[string][]*big.Int{}
	for _, curRhs := range s.Rhs {
		commit.commits[curRhs.Secret] = []*big.Int{}
	}

	// Some constants for commitment generation
	genLimit := new(big.Int).Lsh(big.NewInt(1), s.l2+rangeProofEpsilon+1)
	genOffset := new(big.Int).Lsh(big.NewInt(1), s.l2+rangeProofEpsilon)

	// Build up the range proof randomizers
	for i := 0; i < rangeProofIters; i++ {
		for name, clist := range commit.commits {
			var rval *big.Int
			if name == s.rangeSecret {
				rval = common.RandomBigInt(genLimit)
				rval.Sub(rval, genOffset)
			} else {
				rval = common.RandomBigInt(g.order)
			}
			commit.commits[name] = append(clist, rval)
		}
	}

	// Construct the commitments
	secretMerge := newSecretMerge(&commit, secretdata)
	for i := 0; i < rangeProofIters; i++ {
		commit.i = i
		list = s.RepresentationProofStructure.GenerateCommitmentsFromSecrets(g, list, bases, &secretMerge)
	}

	// Call the logger
	RangeProofLog()

	// Return the result
	return list, commit.RangeCommit
}

func (s *RangeProofStructure) BuildProof(g group, challenge *big.Int, commit RangeCommit, secretdata SecretLookup) RangeProof {
	// For every value, build up results, handling the secret data seperately
	proof := RangeProof{map[string][]*big.Int{}}
	for name, clist := range commit.commits {

		rlist := []*big.Int{}
		if name == s.rangeSecret {
			// special treatment for range secret
			resultOffset := new(big.Int).Lsh(big.NewInt(1), s.l2+rangeProofEpsilon+1)
			l1Offset := new(big.Int).Lsh(big.NewInt(1), s.l1)
			for i := 0; i < rangeProofIters; i++ {
				var res *big.Int
				if challenge.Bit(i) == 1 {
					res = new(big.Int).Sub(new(big.Int).Add(clist[i], l1Offset), secretdata.GetSecret(name))
				} else {
					res = new(big.Int).Set(clist[i])
				}
				res.Add(res, resultOffset)
				rlist = append(rlist, res)
			}
		} else {
			for i := 0; i < rangeProofIters; i++ {
				var res *big.Int
				if challenge.Bit(i) == 1 {
					res = new(big.Int).Mod(new(big.Int).Sub(clist[i], secretdata.GetSecret(name)), g.order)
				} else {
					res = new(big.Int).Set(clist[i])
				}
				rlist = append(rlist, res)
			}
		}
		proof.Results[name] = rlist
	}

	return proof
}

func (s *RangeProofStructure) FakeProof(g group) RangeProof {
	// Some setup
	genLimit := new(big.Int).Lsh(big.NewInt(1), s.l2+rangeProofEpsilon+1)

	proof := RangeProof{map[string][]*big.Int{}}
	for _, curRhs := range s.Rhs {
		if curRhs.Secret == s.rangeSecret {
			rlist := []*big.Int{}
			for i := 0; i < rangeProofIters; i++ {
				rlist = append(rlist, common.RandomBigInt(genLimit))
			}
			proof.Results[curRhs.Secret] = rlist
		} else {
			rlist := []*big.Int{}
			for i := 0; i < rangeProofIters; i++ {
				rlist = append(rlist, common.RandomBigInt(g.order))
			}
			proof.Results[curRhs.Secret] = rlist
		}
	}

	return proof
}

func (s *RangeProofStructure) VerifyProofStructure(proof RangeProof) bool {
	// Validate presence of map
	if proof.Results == nil {
		return false
	}

	// Validate presence of all values
	for _, curRhs := range s.Rhs {
		rlist, ok := proof.Results[curRhs.Secret]
		if !ok {
			return false
		}
		if len(rlist) != rangeProofIters {
			return false
		}
		for _, val := range rlist {
			if val == nil {
				return false
			}
		}
	}

	// Validate size of secret results
	rangeLimit := new(big.Int).Lsh(big.NewInt(1), s.l2+rangeProofEpsilon+2)
	for _, val := range proof.Results[s.rangeSecret] {
		if val.Cmp(rangeLimit) >= 0 {
			return false
		}
	}

	return true
}

type RangeProofResultLookup struct {
	Results map[string]*big.Int
}

func (r *RangeProofResultLookup) GetResult(name string) *big.Int {
	res, ok := r.Results[name]
	if !ok {
		return nil
	}
	return res
}

func (s *RangeProofStructure) GenerateCommitmentsFromProof(g group, list []*big.Int, challenge *big.Int, bases BaseLookup, proof RangeProof) []*big.Int {
	// Some values needed in all iterations
	resultOffset := new(big.Int).Lsh(big.NewInt(1), s.l2+rangeProofEpsilon+1)
	l1Offset := new(big.Int).Lsh(big.NewInt(1), s.l1)

	// Iterate over all indices
	for i := 0; i < rangeProofIters; i++ {
		// Build resultLookup
		resultLookup := RangeProofResultLookup{map[string]*big.Int{}}
		for name, rlist := range proof.Results {
			var res *big.Int
			if name == s.rangeSecret {
				res = new(big.Int).Sub(rlist[i], resultOffset)
				if challenge.Bit(i) == 1 {
					res.Sub(res, l1Offset)
				}
			} else {
				res = new(big.Int).Set(rlist[i])
			}
			resultLookup.Results[name] = res
		}

		// And generate commitment
		list = s.RepresentationProofStructure.GenerateCommitmentsFromProof(g, list, big.NewInt(int64(challenge.Bit(i))), bases, &resultLookup)
	}

	RangeProofLog()

	return list
}
