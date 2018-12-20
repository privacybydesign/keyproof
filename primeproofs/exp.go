package primeproofs

import "github.com/privacybydesign/keyproof/common"
import "github.com/mhe/gabi/big"
import "strings"
import "fmt"

type expProofStructure struct {
	base     string
	exponent string
	mod      string
	result   string
	myname   string
	bitlen   uint

	expBitRep []RepresentationProofStructure
	expBitEq  RepresentationProofStructure

	basePowRep   []RepresentationProofStructure
	basePowRange []RangeProofStructure
	basePowRels  []MultiplicationProofStructure

	startRep RepresentationProofStructure

	interResRep   []RepresentationProofStructure
	interResRange []RangeProofStructure

	interSteps []expStepStructure
}

type expProofCommit struct {
	nameBitEqHider          string
	expBitPederson          []PedersonSecret
	expBitEqHider           *big.Int
	expBitEqHiderRandomizer *big.Int

	basePowPederson    []PedersonSecret
	basePowRangeCommit []RangeCommit
	basePowRelCommit   []MultiplicationProofCommit

	startPederson PedersonSecret

	interResPederson    []PedersonSecret
	interResRangeCommit []RangeCommit

	interStepsCommit []expStepCommit
}

type expProof struct {
	nameBitEqHider string
	ExpBitProofs   []PedersonProof
	ExpBitEqResult *big.Int

	BasePowProofs      []PedersonProof
	BasePowRangeProofs []RangeProof
	BasePowRelProofs   []MultiplicationProof

	StartProof PedersonProof

	InterResProofs      []PedersonProof
	InterResRangeProofs []RangeProof

	InterStepsProofs []expStepProof
}

func (c *expProofCommit) GetSecret(name string) *big.Int {
	if name == c.nameBitEqHider {
		return c.expBitEqHider
	}
	return nil
}

func (c *expProofCommit) GetRandomizer(name string) *big.Int {
	if name == c.nameBitEqHider {
		return c.expBitEqHiderRandomizer
	}
	return nil
}

func (p *expProof) GetResult(name string) *big.Int {
	if name == p.nameBitEqHider {
		return p.ExpBitEqResult
	}
	return nil
}

func newExpProofStructure(base, exponent, mod, result string, bitlen uint) expProofStructure {
	var structure expProofStructure

	structure.base = base
	structure.exponent = exponent
	structure.mod = mod
	structure.result = result
	structure.myname = strings.Join([]string{base, exponent, mod, result, "exp"}, "_")
	structure.bitlen = bitlen

	// Bit representation proofs
	structure.expBitRep = []RepresentationProofStructure{}
	for i := uint(0); i < bitlen; i++ {
		structure.expBitRep = append(
			structure.expBitRep,
			newPedersonRepresentationProofStructure(strings.Join([]string{structure.myname, "bit", fmt.Sprintf("%v", i)}, "_")))
	}

	// Bit equality proof
	structure.expBitEq = RepresentationProofStructure{
		[]LhsContribution{
			LhsContribution{exponent, big.NewInt(-1)},
		},
		[]RhsContribution{
			RhsContribution{"h", strings.Join([]string{structure.myname, "biteqhider"}, "_"), 1},
		},
	}
	for i := uint(0); i < bitlen; i++ {
		structure.expBitEq.Lhs = append(
			structure.expBitEq.Lhs,
			LhsContribution{
				strings.Join([]string{structure.myname, "bit", fmt.Sprintf("%v", i)}, "_"),
				new(big.Int).Lsh(big.NewInt(1), i),
			})
	}

	// Base representation proofs
	structure.basePowRep = []RepresentationProofStructure{}
	for i := uint(0); i < bitlen; i++ {
		structure.basePowRep = append(
			structure.basePowRep,
			newPedersonRepresentationProofStructure(strings.Join([]string{structure.myname, "base", fmt.Sprintf("%v", i)}, "_")))
	}

	// Base range proofs
	structure.basePowRange = []RangeProofStructure{}
	for i := uint(0); i < bitlen; i++ {
		structure.basePowRange = append(
			structure.basePowRange,
			newPedersonRangeProofStructure(strings.Join([]string{structure.myname, "base", fmt.Sprintf("%v", i)}, "_"), 0, bitlen))
	}

	// Base relations proofs
	structure.basePowRels = []MultiplicationProofStructure{}
	for i := uint(0); i < bitlen; i++ {
		if i == 0 {
			// special case for start
			structure.basePowRels = append(
				structure.basePowRels,
				newMultiplicationProofStructure(
					strings.Join([]string{structure.myname, "start"}, "_"),
					base,
					mod,
					strings.Join([]string{structure.myname, "base", fmt.Sprintf("%v", i)}, "_"),
					bitlen))
		} else {
			structure.basePowRels = append(
				structure.basePowRels,
				newMultiplicationProofStructure(
					strings.Join([]string{structure.myname, "base", fmt.Sprintf("%v", i-1)}, "_"),
					strings.Join([]string{structure.myname, "base", fmt.Sprintf("%v", i-1)}, "_"),
					mod,
					strings.Join([]string{structure.myname, "base", fmt.Sprintf("%v", i)}, "_"),
					bitlen))
		}
	}

	// start representation proof
	structure.startRep = RepresentationProofStructure{
		[]LhsContribution{
			LhsContribution{strings.Join([]string{structure.myname, "start"}, "_"), big.NewInt(1)},
			LhsContribution{"g", big.NewInt(-1)},
		},
		[]RhsContribution{
			RhsContribution{"h", strings.Join([]string{structure.myname, "start", "hider"}, "_"), 1},
		},
	}

	// inter representation proofs
	structure.interResRep = []RepresentationProofStructure{}
	for i := uint(0); i < bitlen-1; i++ {
		structure.interResRep = append(
			structure.interResRep,
			newPedersonRepresentationProofStructure(strings.Join([]string{structure.myname, "inter", fmt.Sprintf("%v", i)}, "_")))
	}

	// inter range proofs
	structure.interResRange = []RangeProofStructure{}
	for i := uint(0); i < bitlen-1; i++ {
		structure.interResRange = append(
			structure.interResRange,
			newPedersonRangeProofStructure(strings.Join([]string{structure.myname, "inter", fmt.Sprintf("%v", i)}, "_"), 0, bitlen))
	}

	// step proofs
	structure.interSteps = []expStepStructure{}
	for i := uint(0); i < bitlen; i++ {
		if i == 0 {
			// special case for start
			structure.interSteps = append(
				structure.interSteps,
				newExpStepStructure(
					strings.Join([]string{structure.myname, "bit", fmt.Sprintf("%v", i)}, "_"),
					strings.Join([]string{structure.myname, "start"}, "_"),
					strings.Join([]string{structure.myname, "inter", fmt.Sprintf("%v", i)}, "_"),
					strings.Join([]string{structure.myname, "base", fmt.Sprintf("%v", i)}, "_"),
					mod,
					bitlen))
		} else if i == bitlen-1 {
			// special case for end
			structure.interSteps = append(
				structure.interSteps,
				newExpStepStructure(
					strings.Join([]string{structure.myname, "bit", fmt.Sprintf("%v", i)}, "_"),
					strings.Join([]string{structure.myname, "inter", fmt.Sprintf("%v", i-1)}, "_"),
					result,
					strings.Join([]string{structure.myname, "base", fmt.Sprintf("%v", i)}, "_"),
					mod,
					bitlen))
		} else {
			structure.interSteps = append(
				structure.interSteps,
				newExpStepStructure(
					strings.Join([]string{structure.myname, "bit", fmt.Sprintf("%v", i)}, "_"),
					strings.Join([]string{structure.myname, "inter", fmt.Sprintf("%v", i-1)}, "_"),
					strings.Join([]string{structure.myname, "inter", fmt.Sprintf("%v", i)}, "_"),
					strings.Join([]string{structure.myname, "base", fmt.Sprintf("%v", i)}, "_"),
					mod,
					bitlen))
		}
	}

	return structure
}

func (s *expProofStructure) GenerateCommitmentsFromSecrets(g group, list []*big.Int, bases BaseLookup, secretdata SecretLookup) ([]*big.Int, expProofCommit) {
	var commit expProofCommit

	// Build up commit structure

	// exponent bits
	commit.nameBitEqHider = strings.Join([]string{s.myname, "biteqhider"}, "_")
	commit.expBitEqHider = new(big.Int).Neg(secretdata.GetSecret(strings.Join([]string{s.exponent, "hider"}, "_")))
	commit.expBitEqHiderRandomizer = common.RandomBigInt(g.order)
	commit.expBitPederson = []PedersonSecret{}
	for i := uint(0); i < s.bitlen; i++ {
		commit.expBitPederson = append(
			commit.expBitPederson,
			newPedersonSecret(
				g,
				strings.Join([]string{s.myname, "bit", fmt.Sprintf("%v", i)}, "_"),
				big.NewInt(int64(secretdata.GetSecret(s.exponent).Bit(int(i))))))
		commit.expBitEqHider.Add(
			commit.expBitEqHider,
			new(big.Int).Lsh(commit.expBitPederson[i].hider, i))
	}
	commit.expBitEqHider.Mod(commit.expBitEqHider, g.order)

	// base powers
	commit.basePowPederson = []PedersonSecret{}
	for i := uint(0); i < s.bitlen; i++ {
		commit.basePowPederson = append(
			commit.basePowPederson,
			newPedersonSecret(
				g,
				strings.Join([]string{s.myname, "base", fmt.Sprintf("%v", i)}, "_"),
				new(big.Int).Exp(
					secretdata.GetSecret(s.base),
					new(big.Int).Lsh(big.NewInt(1), i),
					secretdata.GetSecret(s.mod))))
	}

	// Start pederson
	commit.startPederson = newPedersonSecret(
		g,
		strings.Join([]string{s.myname, "start"}, "_"),
		big.NewInt(1))

	// intermediate results
	curInterRes := big.NewInt(1)
	commit.interResPederson = []PedersonSecret{}
	for i := uint(0); i < s.bitlen-1; i++ {
		if secretdata.GetSecret(s.exponent).Bit(int(i)) == 1 {
			curInterRes.Mod(
				new(big.Int).Mul(
					curInterRes,
					new(big.Int).Exp(
						secretdata.GetSecret(s.base),
						new(big.Int).Lsh(big.NewInt(1), i),
						secretdata.GetSecret(s.mod))),
				secretdata.GetSecret(s.mod))
			if curInterRes.Cmp(new(big.Int).Sub(secretdata.GetSecret(s.mod), big.NewInt(1))) == 0 {
				curInterRes.SetInt64(-1) // ugly(ish) hack to make comparisons to -1 work
			}
		}
		commit.interResPederson = append(
			commit.interResPederson,
			newPedersonSecret(
				g,
				strings.Join([]string{s.myname, "inter", fmt.Sprintf("%v", i)}, "_"),
				curInterRes))
	}

	// inner bases and secrets (this is ugly code, hopefully go2 will make this better someday)
	baseList := []BaseLookup{}
	secretList := []SecretLookup{}
	for i, _ := range commit.expBitPederson {
		baseList = append(baseList, &commit.expBitPederson[i])
		secretList = append(secretList, &commit.expBitPederson[i])
	}
	for i, _ := range commit.basePowPederson {
		baseList = append(baseList, &commit.basePowPederson[i])
		secretList = append(secretList, &commit.basePowPederson[i])
	}
	baseList = append(baseList, &commit.startPederson)
	secretList = append(secretList, &commit.startPederson)
	for i, _ := range commit.interResPederson {
		baseList = append(baseList, &commit.interResPederson[i])
		secretList = append(secretList, &commit.interResPederson[i])
	}
	baseList = append(baseList, bases)
	secretList = append(secretList, secretdata)
	secretList = append(secretList, &commit)
	innerBases := newBaseMerge(baseList...)
	innerSecrets := newSecretMerge(secretList...)

	// Generate commitment list
	// bits
	for i, _ := range commit.expBitPederson {
		list = commit.expBitPederson[i].GenerateCommitments(list)
	}
	for _, bitrep := range s.expBitRep {
		list = bitrep.GenerateCommitmentsFromSecrets(g, list, &innerBases, &innerSecrets)
	}
	list = s.expBitEq.GenerateCommitmentsFromSecrets(g, list, &innerBases, &innerSecrets)

	//base
	for i, _ := range commit.basePowPederson {
		list = commit.basePowPederson[i].GenerateCommitments(list)
	}
	for i, _ := range s.basePowRep {
		list = s.basePowRep[i].GenerateCommitmentsFromSecrets(g, list, &innerBases, &innerSecrets)
	}
	commit.basePowRangeCommit = []RangeCommit{}
	for i, _ := range s.basePowRange {
		var rc RangeCommit
		list, rc = s.basePowRange[i].GenerateCommitmentsFromSecrets(g, list, &innerBases, &innerSecrets)
		commit.basePowRangeCommit = append(commit.basePowRangeCommit, rc)
	}
	commit.basePowRelCommit = []MultiplicationProofCommit{}
	for i, _ := range s.basePowRels {
		var rc MultiplicationProofCommit
		list, rc = s.basePowRels[i].GenerateCommitmentsFromSecrets(g, list, &innerBases, &innerSecrets)
		commit.basePowRelCommit = append(commit.basePowRelCommit, rc)
	}

	//start
	list = commit.startPederson.GenerateCommitments(list)
	list = s.startRep.GenerateCommitmentsFromSecrets(g, list, &innerBases, &innerSecrets)

	// interres
	for i, _ := range commit.interResPederson {
		list = commit.interResPederson[i].GenerateCommitments(list)
	}
	for i, _ := range s.interResRep {
		list = s.interResRep[i].GenerateCommitmentsFromSecrets(g, list, &innerBases, &innerSecrets)
	}
	commit.interResRangeCommit = []RangeCommit{}
	for i, _ := range s.interResRange {
		var rc RangeCommit
		list, rc = s.interResRange[i].GenerateCommitmentsFromSecrets(g, list, &innerBases, &innerSecrets)
		commit.interResRangeCommit = append(commit.interResRangeCommit, rc)
	}

	// steps
	commit.interStepsCommit = []expStepCommit{}
	for i, _ := range s.interSteps {
		if !s.interSteps[i].IsTrue(&innerSecrets) {
			fmt.Printf("%v %v %v %v %v\n", commit.expBitPederson[i].secret, commit.interResPederson[i-1].secret, commit.interResPederson[i].secret, commit.basePowPederson[i].secret, secretdata.GetSecret(s.mod))
			panic(fmt.Sprintf("aah %v", i))
		}
		var ec expStepCommit
		list, ec = s.interSteps[i].GenerateCommitmentsFromSecrets(g, list, &innerBases, &innerSecrets)
		commit.interStepsCommit = append(commit.interStepsCommit, ec)
	}

	return list, commit
}

func (s *expProofStructure) BuildProof(g group, challenge *big.Int, commit expProofCommit, secretdata SecretLookup) expProof {
	var proof expProof

	// inner secret data
	secretList := []SecretLookup{}
	for i, _ := range commit.expBitPederson {
		secretList = append(secretList, &commit.expBitPederson[i])
	}
	for i, _ := range commit.basePowPederson {
		secretList = append(secretList, &commit.basePowPederson[i])
	}
	secretList = append(secretList, &commit.startPederson)
	for i, _ := range commit.interResPederson {
		secretList = append(secretList, &commit.interResPederson[i])
	}
	secretList = append(secretList, secretdata)
	secretList = append(secretList, &commit)
	innerSecrets := newSecretMerge(secretList...)

	//bit proofs
	proof.ExpBitProofs = []PedersonProof{}
	for _, expbit := range commit.expBitPederson {
		proof.ExpBitProofs = append(proof.ExpBitProofs, expbit.BuildProof(g, challenge))
	}

	//base proofs
	proof.BasePowProofs = []PedersonProof{}
	for _, basePow := range commit.basePowPederson {
		proof.BasePowProofs = append(proof.BasePowProofs, basePow.BuildProof(g, challenge))
	}
	proof.BasePowRangeProofs = []RangeProof{}
	for i, _ := range commit.basePowRangeCommit {
		proof.BasePowRangeProofs = append(
			proof.BasePowRangeProofs,
			s.basePowRange[i].BuildProof(g, challenge, commit.basePowRangeCommit[i], &innerSecrets))
	}
	proof.BasePowRelProofs = []MultiplicationProof{}
	for i, _ := range commit.basePowRelCommit {
		proof.BasePowRelProofs = append(
			proof.BasePowRelProofs,
			s.basePowRels[i].BuildProof(g, challenge, commit.basePowRelCommit[i], &innerSecrets))
	}

	// start proof
	proof.StartProof = commit.startPederson.BuildProof(g, challenge)

	// interres proofs
	proof.InterResProofs = []PedersonProof{}
	for i, _ := range commit.interResPederson {
		proof.InterResProofs = append(proof.InterResProofs, commit.interResPederson[i].BuildProof(g, challenge))
	}
	proof.InterResRangeProofs = []RangeProof{}
	for i, _ := range commit.interResRangeCommit {
		proof.InterResRangeProofs = append(
			proof.InterResRangeProofs,
			s.interResRange[i].BuildProof(g, challenge, commit.interResRangeCommit[i], &innerSecrets))
	}

	// step proofs
	proof.InterStepsProofs = []expStepProof{}
	for i, _ := range commit.interStepsCommit {
		proof.InterStepsProofs = append(
			proof.InterStepsProofs,
			s.interSteps[i].BuildProof(g, challenge, commit.interStepsCommit[i], &innerSecrets))
	}

	// Calculate our segments of the proof
	proof.ExpBitEqResult = new(big.Int).Mod(
		new(big.Int).Sub(
			commit.expBitEqHiderRandomizer,
			new(big.Int).Mul(
				challenge,
				commit.expBitEqHider)),
		g.order)

	return proof
}

func (s *expProofStructure) FakeProof(g group, challenge *big.Int) expProof {
	var proof expProof

	proof.ExpBitEqResult = common.RandomBigInt(g.order)
	proof.ExpBitProofs = []PedersonProof{}
	for i := uint(0); i < s.bitlen; i++ {
		proof.ExpBitProofs = append(proof.ExpBitProofs, newPedersonFakeProof(g))
	}

	proof.BasePowProofs = []PedersonProof{}
	proof.BasePowRangeProofs = []RangeProof{}
	proof.BasePowRelProofs = []MultiplicationProof{}
	for i, _ := range s.basePowRep {
		proof.BasePowProofs = append(proof.BasePowProofs, newPedersonFakeProof(g))
		proof.BasePowRangeProofs = append(proof.BasePowRangeProofs, s.basePowRange[i].FakeProof(g))
		proof.BasePowRelProofs = append(proof.BasePowRelProofs, s.basePowRels[i].FakeProof(g))
	}

	proof.StartProof = newPedersonFakeProof(g)

	proof.InterResProofs = []PedersonProof{}
	proof.InterResRangeProofs = []RangeProof{}

	for i, _ := range s.interResRep {
		proof.InterResProofs = append(proof.InterResProofs, newPedersonFakeProof(g))
		proof.InterResRangeProofs = append(proof.InterResRangeProofs, s.interResRange[i].FakeProof(g))
	}

	proof.InterStepsProofs = []expStepProof{}
	for i, _ := range s.interSteps {
		proof.InterStepsProofs = append(proof.InterStepsProofs, s.interSteps[i].FakeProof(g, challenge))
	}

	return proof
}

func (s *expProofStructure) VerifyProofStructure(challenge *big.Int, proof expProof) bool {
	// check bit proofs
	if proof.ExpBitEqResult == nil || len(proof.ExpBitProofs) != int(s.bitlen) {
		return false
	}
	for i, _ := range proof.ExpBitProofs {
		if !proof.ExpBitProofs[i].VerifyStructure() {
			return false
		}
	}

	// check base proofs
	if len(proof.BasePowProofs) != int(s.bitlen) || len(proof.BasePowRangeProofs) != int(s.bitlen) || len(proof.BasePowRelProofs) != int(s.bitlen) {
		return false
	}
	for i, _ := range proof.BasePowProofs {
		if !proof.BasePowProofs[i].VerifyStructure() ||
			!s.basePowRange[i].VerifyProofStructure(proof.BasePowRangeProofs[i]) ||
			!s.basePowRels[i].VerifyProofStructure(proof.BasePowRelProofs[i]) {
			return false
		}
	}

	// check start proof
	if !proof.StartProof.VerifyStructure() {
		return false
	}

	// check inter res
	if len(proof.InterResProofs) != int(s.bitlen-1) || len(proof.InterResRangeProofs) != int(s.bitlen-1) {
		return false
	}
	for i, _ := range proof.InterResProofs {
		if !proof.InterResProofs[i].VerifyStructure() ||
			!s.interResRange[i].VerifyProofStructure(proof.InterResRangeProofs[i]) {
			return false
		}
	}

	// check step proof
	if len(proof.InterStepsProofs) != int(s.bitlen) {
		return false
	}
	for i, _ := range proof.InterStepsProofs {
		if !s.interSteps[i].VerifyProofStructure(challenge, proof.InterStepsProofs[i]) {
			return false
		}
	}

	return true
}

func (s *expProofStructure) GenerateCommitmentsFromProof(g group, list []*big.Int, challenge *big.Int, bases BaseLookup, proofdata ProofLookup, proof expProof) []*big.Int {
	// inner bases and proofs (again hopefully go2 will make this better)
	baseList := []BaseLookup{}
	proofList := []ProofLookup{}
	for i, _ := range proof.ExpBitProofs {
		proof.ExpBitProofs[i].SetName(strings.Join([]string{s.myname, "bit", fmt.Sprintf("%v", i)}, "_"))
		baseList = append(baseList, &proof.ExpBitProofs[i])
		proofList = append(proofList, &proof.ExpBitProofs[i])
	}
	for i, _ := range proof.BasePowProofs {
		proof.BasePowProofs[i].SetName(strings.Join([]string{s.myname, "base", fmt.Sprintf("%v", i)}, "_"))
		baseList = append(baseList, &proof.BasePowProofs[i])
		proofList = append(proofList, &proof.BasePowProofs[i])
	}
	proof.StartProof.SetName(strings.Join([]string{s.myname, "start"}, "_"))
	baseList = append(baseList, &proof.StartProof)
	proofList = append(proofList, &proof.StartProof)
	for i, _ := range proof.InterResProofs {
		proof.InterResProofs[i].SetName(strings.Join([]string{s.myname, "inter", fmt.Sprintf("%v", i)}, "_"))
		baseList = append(baseList, &proof.InterResProofs[i])
		proofList = append(proofList, &proof.InterResProofs[i])
	}
	baseList = append(baseList, bases)
	proofList = append(proofList, proofdata)
	proof.nameBitEqHider = strings.Join([]string{s.myname, "biteqhider"}, "_")
	proofList = append(proofList, &proof)
	innerBases := newBaseMerge(baseList...)
	innerProof := newProofMerge(proofList...)

	// Generate commitment list
	// bit
	for i, _ := range proof.ExpBitProofs {
		list = proof.ExpBitProofs[i].GenerateCommitments(list)
	}
	for _, bitrep := range s.expBitRep {
		list = bitrep.GenerateCommitmentsFromProof(g, list, challenge, &innerBases, &innerProof)
	}
	list = s.expBitEq.GenerateCommitmentsFromProof(g, list, challenge, &innerBases, &innerProof)

	//base
	for i, _ := range proof.BasePowProofs {
		list = proof.BasePowProofs[i].GenerateCommitments(list)
	}
	for i, _ := range s.basePowRep {
		list = s.basePowRep[i].GenerateCommitmentsFromProof(g, list, challenge, &innerBases, &innerProof)
	}
	for i, _ := range s.basePowRange {
		list = s.basePowRange[i].GenerateCommitmentsFromProof(g, list, challenge, &innerBases, proof.BasePowRangeProofs[i])
	}
	for i, _ := range s.basePowRels {
		list = s.basePowRels[i].GenerateCommitmentsFromProof(g, list, challenge, &innerBases, &innerProof, proof.BasePowRelProofs[i])
	}

	// start
	list = proof.StartProof.GenerateCommitments(list)
	list = s.startRep.GenerateCommitmentsFromProof(g, list, challenge, &innerBases, &innerProof)

	// interres
	for i, _ := range proof.InterResProofs {
		list = proof.InterResProofs[i].GenerateCommitments(list)
	}
	for i, _ := range s.interResRep {
		list = s.interResRep[i].GenerateCommitmentsFromProof(g, list, challenge, &innerBases, &innerProof)
	}
	for i, _ := range s.interResRange {
		list = s.interResRange[i].GenerateCommitmentsFromProof(g, list, challenge, &innerBases, proof.InterResRangeProofs[i])
	}

	// steps
	for i, _ := range s.interSteps {
		list = s.interSteps[i].GenerateCommitmentsFromProof(g, list, challenge, &innerBases, proof.InterStepsProofs[i])
	}

	return list
}

func (s *expProofStructure) IsTrue(secretdata SecretLookup) bool {
	div := new(big.Int)
	mod := new(big.Int)

	div.DivMod(
		new(big.Int).Sub(
			new(big.Int).Exp(
				secretdata.GetSecret(s.base),
				secretdata.GetSecret(s.exponent),
				secretdata.GetSecret(s.mod)),
			secretdata.GetSecret(s.result)),
		secretdata.GetSecret(s.mod),
		mod)

	return mod.Cmp(big.NewInt(0)) == 0 && uint(div.BitLen()) <= s.bitlen
}