package primeproofs

import "github.com/privacybydesign/keyproof/common"
import "github.com/privacybydesign/gabi/big"
import "strings"
import "fmt"

type IsSquareProofStructure struct {
	N       *big.Int
	Squares []*big.Int

	NRep RepresentationProofStructure

	SquaresRep []RepresentationProofStructure
	RootsRep   []RepresentationProofStructure
	RootsRange []RangeProofStructure
	RootsValid []MultiplicationProofStructure
}

type IsSquareProof struct {
	NProof          PedersonProof
	SquaresProof    []PedersonProof
	RootsProof      []PedersonProof
	RootsRangeProof []RangeProof
	RootsValidProof []MultiplicationProof
}

type isSquareProofCommit struct {
	squares []PedersonSecret
	roots   []PedersonSecret
	n       PedersonSecret

	rootRangeCommit []RangeCommit
	rootValidCommit []MultiplicationProofCommit
}

func NewIsSquareProofStructure(N *big.Int, Squares []*big.Int) IsSquareProofStructure {
	var result IsSquareProofStructure

	// Copy over primary values
	result.N = new(big.Int).Set(N)
	result.Squares = make([]*big.Int, len(Squares))
	for i, val := range Squares {
		result.Squares[i] = new(big.Int).Set(val)
	}

	// Setup representation proof of N
	result.NRep = RepresentationProofStructure{
		[]LhsContribution{
			LhsContribution{"N", big.NewInt(-1)},
			LhsContribution{"g", new(big.Int).Set(N)},
		},
		[]RhsContribution{
			RhsContribution{"h", "N_hider", -1},
		},
	}

	// Setup representation proofs of squares
	result.SquaresRep = make([]RepresentationProofStructure, len(Squares))
	for i, val := range result.Squares {
		result.SquaresRep[i] = RepresentationProofStructure{
			[]LhsContribution{
				LhsContribution{strings.Join([]string{"s", fmt.Sprintf("%v", i)}, "_"), big.NewInt(-1)},
				LhsContribution{"g", new(big.Int).Set(val)},
			},
			[]RhsContribution{
				RhsContribution{"h", strings.Join([]string{"s", fmt.Sprintf("%v", i), "hider"}, "_"), -1},
			},
		}
	}

	// Setup representation proofs of roots
	result.RootsRep = make([]RepresentationProofStructure, len(Squares))
	for i, _ := range Squares {
		result.RootsRep[i] = newPedersonRepresentationProofStructure(
			strings.Join([]string{"r", fmt.Sprintf("%v", i)}, "_"))
	}

	// Setup range proof of roots
	result.RootsRange = make([]RangeProofStructure, len(Squares))
	for i, _ := range Squares {
		result.RootsRange[i] = newPedersonRangeProofStructure(
			strings.Join([]string{"r", fmt.Sprintf("%v", i)}, "_"),
			0,
			uint(N.BitLen()))
	}

	// Setup proofs that the roots are roots
	result.RootsValid = make([]MultiplicationProofStructure, len(Squares))
	for i, _ := range Squares {
		result.RootsValid[i] = newMultiplicationProofStructure(
			strings.Join([]string{"r", fmt.Sprintf("%v", i)}, "_"),
			strings.Join([]string{"r", fmt.Sprintf("%v", i)}, "_"),
			"N",
			strings.Join([]string{"s", fmt.Sprintf("%v", i)}, "_"),
			uint(N.BitLen()))
	}

	return result
}

func (s *IsSquareProofStructure) NumRangeProofs() int {
	var result int = 0
	for _, ms := range s.RootsValid {
		result += ms.NumRangeProofs()
	}

	return result + len(s.RootsRange)
}

func (s *IsSquareProofStructure) NumCommitments() int {
	// Constants
	res := 1 + len(s.Squares)
	// Pedersons
	res += 1
	res += len(s.Squares)
	res += len(s.Squares)
	// Representationproofs
	res += 1
	res += len(s.SquaresRep)
	res += len(s.RootsRep)
	// ValidityProofs
	for i, _ := range s.RootsRange {
		res += s.RootsRange[i].NumCommitments()
	}
	for i, _ := range s.RootsValid {
		res += s.RootsValid[i].NumCommitments()
	}
	return res
}

func (s *IsSquareProofStructure) GenerateCommitmentsFromSecrets(g group, list []*big.Int, P *big.Int, Q *big.Int) ([]*big.Int, isSquareProofCommit) {
	var commit isSquareProofCommit

	// Build up the secrets
	commit.squares = make([]PedersonSecret, len(s.Squares))
	for i, val := range s.Squares {
		commit.squares[i] = newPedersonSecret(g, strings.Join([]string{"s", fmt.Sprintf("%v", i)}, "_"), val)
	}
	commit.roots = make([]PedersonSecret, len(s.Squares))
	for i, val := range s.Squares {
		root, ok := common.ModSqrt(val, []*big.Int{P, Q})
		if !ok {
			panic("Incorrect key")
		}
		commit.roots[i] = newPedersonSecret(g, strings.Join([]string{"r", fmt.Sprintf("%v", i)}, "_"), root)
	}
	commit.n = newPedersonSecret(g, "N", s.N)

	// Build up bases and secrets (this is ugly code, hopefully go2 will make this better someday)
	var baseList = []BaseLookup{}
	var secretList = []SecretLookup{}
	for i, _ := range commit.squares {
		baseList = append(baseList, &commit.squares[i])
		secretList = append(secretList, &commit.squares[i])
	}
	for i, _ := range commit.roots {
		baseList = append(baseList, &commit.roots[i])
		secretList = append(secretList, &commit.roots[i])
	}
	baseList = append(baseList, &commit.n)
	secretList = append(secretList, &commit.n)
	baseList = append(baseList, &g)
	bases := newBaseMerge(baseList...)
	secrets := newSecretMerge(secretList...)

	// Generate commitments
	commit.rootRangeCommit = make([]RangeCommit, len(s.Squares))
	commit.rootValidCommit = make([]MultiplicationProofCommit, len(s.Squares))
	list = append(list, s.N)
	for _, val := range s.Squares {
		list = append(list, val)
	}
	list = commit.n.GenerateCommitments(list)
	for i, _ := range commit.squares {
		list = commit.squares[i].GenerateCommitments(list)
	}
	for i, _ := range commit.roots {
		list = commit.roots[i].GenerateCommitments(list)
	}
	list = s.NRep.GenerateCommitmentsFromSecrets(g, list, &bases, &secrets)
	for i, _ := range s.SquaresRep {
		list = s.SquaresRep[i].GenerateCommitmentsFromSecrets(g, list, &bases, &secrets)
	}
	for i, _ := range s.RootsRep {
		list = s.RootsRep[i].GenerateCommitmentsFromSecrets(g, list, &bases, &secrets)
	}
	for i, _ := range s.RootsRange {
		list, commit.rootRangeCommit[i] = s.RootsRange[i].GenerateCommitmentsFromSecrets(g, list, &bases, &secrets)
	}
	for i, _ := range s.RootsValid {
		list, commit.rootValidCommit[i] = s.RootsValid[i].GenerateCommitmentsFromSecrets(g, list, &bases, &secrets)
	}

	return list, commit
}

func (s *IsSquareProofStructure) BuildProof(g group, challenge *big.Int, commit isSquareProofCommit) IsSquareProof {
	// Build up secrets (this is ugly code, hopefully go2 will make this better someday)
	var secretList = []SecretLookup{}
	for i, _ := range commit.squares {
		secretList = append(secretList, &commit.squares[i])
	}
	for i, _ := range commit.roots {
		secretList = append(secretList, &commit.roots[i])
	}
	secretList = append(secretList, &commit.n)
	secrets := newSecretMerge(secretList...)

	// Calculate proofs
	var proof IsSquareProof
	proof.NProof = commit.n.BuildProof(g, challenge)
	proof.SquaresProof = make([]PedersonProof, len(s.Squares))
	for i, _ := range commit.squares {
		proof.SquaresProof[i] = commit.squares[i].BuildProof(g, challenge)
	}
	proof.RootsProof = make([]PedersonProof, len(s.Squares))
	for i, _ := range commit.roots {
		proof.RootsProof[i] = commit.roots[i].BuildProof(g, challenge)
	}
	proof.RootsRangeProof = make([]RangeProof, len(s.Squares))
	for i, _ := range s.RootsRange {
		proof.RootsRangeProof[i] = s.RootsRange[i].BuildProof(g, challenge, commit.rootRangeCommit[i], &secrets)
	}
	proof.RootsValidProof = make([]MultiplicationProof, len(s.Squares))
	for i, _ := range s.RootsValid {
		proof.RootsValidProof[i] = s.RootsValid[i].BuildProof(g, challenge, commit.rootValidCommit[i], &secrets)
	}

	return proof
}

func (s *IsSquareProofStructure) VerifyProofStructure(proof IsSquareProof) bool {
	if !proof.NProof.VerifyStructure() {
		return false
	}
	if len(proof.SquaresProof) != len(s.Squares) || len(proof.RootsProof) != len(s.Squares) {
		return false
	}
	if len(proof.RootsRangeProof) != len(s.Squares) || len(proof.RootsValidProof) != len(s.Squares) {
		return false
	}
	for i, _ := range s.Squares {
		if !proof.SquaresProof[i].VerifyStructure() || !proof.RootsProof[i].VerifyStructure() {
			return false
		}
		if !s.RootsRange[i].VerifyProofStructure(proof.RootsRangeProof[i]) {
			return false
		}
		if !s.RootsValid[i].VerifyProofStructure(proof.RootsValidProof[i]) {
			return false
		}
	}

	return true
}

func (s *IsSquareProofStructure) GenerateCommitmentsFromProof(g group, list []*big.Int, challenge *big.Int, proof IsSquareProof) []*big.Int {
	// Setup names in pederson proofs
	proof.NProof.SetName("N")
	for i, _ := range s.Squares {
		proof.SquaresProof[i].SetName(strings.Join([]string{"s", fmt.Sprintf("%v", i)}, "_"))
		proof.RootsProof[i].SetName(strings.Join([]string{"r", fmt.Sprintf("%v", i)}, "_"))
	}

	// Build up bases and proofs mergers
	var baseList = []BaseLookup{}
	var proofList = []ProofLookup{}
	for i, _ := range s.Squares {
		baseList = append(baseList, &proof.SquaresProof[i])
		proofList = append(proofList, &proof.SquaresProof[i])
	}
	for i, _ := range s.Squares {
		baseList = append(baseList, &proof.RootsProof[i])
		proofList = append(proofList, &proof.RootsProof[i])
	}
	baseList = append(baseList, &proof.NProof)
	proofList = append(proofList, &proof.NProof)
	baseList = append(baseList, &g)
	var bases = newBaseMerge(baseList...)
	var proofs = newProofMerge(proofList...)

	// Build up commitment list
	list = append(list, s.N)
	for _, val := range s.Squares {
		list = append(list, val)
	}
	list = proof.NProof.GenerateCommitments(list)
	for i, _ := range s.Squares {
		list = proof.SquaresProof[i].GenerateCommitments(list)
	}
	for i, _ := range s.Squares {
		list = proof.RootsProof[i].GenerateCommitments(list)
	}
	list = s.NRep.GenerateCommitmentsFromProof(g, list, challenge, &bases, &proofs)
	for i, _ := range s.Squares {
		list = s.SquaresRep[i].GenerateCommitmentsFromProof(g, list, challenge, &bases, &proofs)
	}
	for i, _ := range s.Squares {
		list = s.RootsRep[i].GenerateCommitmentsFromProof(g, list, challenge, &bases, &proofs)
	}
	for i, _ := range s.Squares {
		list = s.RootsRange[i].GenerateCommitmentsFromProof(g, list, challenge, &bases, proof.RootsRangeProof[i])
	}
	for i, _ := range s.Squares {
		list = s.RootsValid[i].GenerateCommitmentsFromProof(g, list, challenge, &bases, &proofs, proof.RootsValidProof[i])
	}

	return list
}
