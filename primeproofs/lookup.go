package primeproofs

import "github.com/privacybydesign/gabi/big"
import "github.com/bwesterb/go-exptable"

type BaseLookup interface {
	GetBase(name string) *big.Int
	Exp(name string, exp, P *big.Int) *big.Int
}

type SecretLookup interface {
	GetSecret(name string) *big.Int
	GetRandomizer(name string) *big.Int
}

type ProofLookup interface {
	GetResult(name string) *big.Int
}

func (g *group) Exp(name string, exp, P *big.Int) *big.Int {
	var table *exptable.Table
	var ret big.Int
	if name == "g" {
		table = &g.gTable
	} else if name == "h" {
		table = &g.hTable
	} else {
		return nil
	}
	var exp2 big.Int
	exp2.Mod(exp, g.order)
	table.Exp(ret.Value(), exp2.Value())
	return &ret
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

func (b *BaseMerge) Exp(name string, exp, P *big.Int) *big.Int {
	for _, part := range b.parts {
		res := part.Exp(name, exp, P)
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
