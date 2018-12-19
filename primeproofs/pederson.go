package primeproofs

import "github.com/mhe/gabi/big"
import "strings"

type PedersonSecret struct {
	name             string
	hname            string
	secret           *big.Int
	secretRandomizer *big.Int
	hider            *big.Int
	hiderRandomizer  *big.Int
	commit           *big.Int
}

type PedersonProof struct {
	name    string
	hname   string
	Commit  *big.Int
	Sresult *big.Int
	Hresult *big.Int
}

func newPedersonRepresentationProofStructure(name string) RepresentationProofStructure {
	var structure RepresentationProofStructure
	structure.Lhs = []LhsContribution{
		LhsContribution{name, big.NewInt(1)},
	}
	structure.Rhs = []RhsContribution{
		RhsContribution{"g", name, 1},
		RhsContribution{"h", strings.Join([]string{name, "hider"}, "_"), 1},
	}
	return structure
}

func newPedersonRangeProofStructure(name string, l1 uint, l2 uint) RangeProofStructure {
	var structure RangeProofStructure
	structure.Lhs = []LhsContribution{
		LhsContribution{name, big.NewInt(1)},
	}
	structure.Rhs = []RhsContribution{
		RhsContribution{"g", name, 1},
		RhsContribution{"h", strings.Join([]string{name, "hider"}, "_"), 1},
	}
	structure.rangeSecret = name
	structure.l1 = l1
	structure.l2 = l2
	return structure
}

func newPedersonSecret(g group, name string, value *big.Int) PedersonSecret {
	var result PedersonSecret
	result.name = name
	result.hname = strings.Join([]string{name, "hider"}, "_")
	result.secret = new(big.Int).Set(value)
	result.secretRandomizer = randomBigInt(g.order)
	result.hider = randomBigInt(g.order)
	result.hiderRandomizer = randomBigInt(g.order)
	result.commit = new(big.Int).Mod(
		new(big.Int).Mul(
			new(big.Int).Exp(g.g, result.secret, g.P),
			new(big.Int).Exp(g.h, result.hider, g.P)),
		g.P)
	return result
}

func newPedersonFakeProof(g group) PedersonProof {
	var result PedersonProof
	result.Commit = new(big.Int).Mod(
		new(big.Int).Mul(
			new(big.Int).Exp(g.g, randomBigInt(g.order), g.P),
			new(big.Int).Exp(g.h, randomBigInt(g.order), g.P)),
		g.P)
	result.Sresult = randomBigInt(g.order)
	result.Hresult = randomBigInt(g.order)
	return result
}

func (s *PedersonSecret) BuildProof(g group, challenge *big.Int) PedersonProof {
	var result PedersonProof
	result.Commit = s.commit
	result.Sresult = new(big.Int).Mod(new(big.Int).Sub(s.secretRandomizer, new(big.Int).Mul(challenge, s.secret)), g.order)
	result.Hresult = new(big.Int).Mod(new(big.Int).Sub(s.hiderRandomizer, new(big.Int).Mul(challenge, s.hider)), g.order)
	return result
}

func (s *PedersonSecret) GenerateCommitments(list []*big.Int) []*big.Int {
	return append(list, s.commit)
}

func (s *PedersonSecret) GetSecret(name string) *big.Int {
	if name == s.name {
		return s.secret
	}
	if name == s.hname {
		return s.hider
	}
	return nil
}

func (s *PedersonSecret) GetRandomizer(name string) *big.Int {
	if name == s.name {
		return s.secretRandomizer
	}
	if name == s.hname {
		return s.hiderRandomizer
	}
	return nil
}

func (c *PedersonSecret) GetBase(name string) *big.Int {
	if name == c.name {
		return c.commit
	}
	return nil
}

func (p *PedersonProof) SetName(name string) {
	p.name = name
	p.hname = strings.Join([]string{name, "hider"}, "_")
}

func (p *PedersonProof) GenerateCommitments(list []*big.Int) []*big.Int {
	return append(list, p.Commit)
}

func (p *PedersonProof) VerifyStructure() bool {
	return p.Commit != nil && p.Sresult != nil && p.Hresult != nil
}

func (p *PedersonProof) GetBase(name string) *big.Int {
	if name == p.name {
		return p.Commit
	}
	return nil
}

func (p *PedersonProof) GetResult(name string) *big.Int {
	if name == p.name {
		return p.Sresult
	}
	if name == p.hname {
		return p.Hresult
	}
	return nil
}
