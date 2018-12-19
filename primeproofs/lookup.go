package primeproofs

import "github.com/mhe/gabi/big"

type BaseLookup interface {
	GetBase(name string) *big.Int
}

type SecretLookup interface {
	GetSecret(name string) *big.Int
	GetRandomizer(name string) *big.Int
}

type ProofLookup interface {
	GetResult(name string) *big.Int
}

func (g *group) GetBase(name string) *big.Int {
	if name == "g" {
		return g.g
	}
	if name == "h" {
		return g.h
	}
	return nil
}

type BaseMerge struct {
	parts []BaseLookup
}

func newBaseMerge(parts ...BaseLookup) BaseMerge {
	var result BaseMerge
	result.parts = parts
	return result
}

func (b *BaseMerge) GetBase(name string) *big.Int {
	for _, part := range b.parts {
		res := part.GetBase(name)
		if res != nil {
			return res
		}
	}
	return nil
}

type SecretMerge struct {
	parts []SecretLookup
}

func newSecretMerge(parts ...SecretLookup) SecretMerge {
	var result SecretMerge
	result.parts = parts
	return result
}

func (s *SecretMerge) GetSecret(name string) *big.Int {
	for _, part := range s.parts {
		res := part.GetSecret(name)
		if res != nil {
			return res
		}
	}
	return nil
}

func (s *SecretMerge) GetRandomizer(name string) *big.Int {
	for _, part := range s.parts {
		res := part.GetRandomizer(name)
		if res != nil {
			return res
		}
	}
	return nil
}

type ProofMerge struct {
	parts []ProofLookup
}

func newProofMerge(parts ...ProofLookup) ProofMerge {
	var result ProofMerge
	result.parts = parts
	return result
}

func (p *ProofMerge) GetResult(name string) *big.Int {
	for _, part := range p.parts {
		res := part.GetResult(name)
		if res != nil {
			return res
		}
	}
	return nil
}
