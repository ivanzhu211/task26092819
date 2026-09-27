package sgrules

import (
	"fmt"
	"math/rand"
	"testing"
)

// genWideRules builds n rules with wide-ranging CIDRs and port ranges to
// maximize the atomic-cell count (worst case for the analysis engine).
func genWideRules(rng *rand.Rand, n int) []Rule {
	ids := rng.Perm(n)
	rules := make([]Rule, 0, n)
	for i := 0; i < n; i++ {
		r := Rule{
			ID:       uint32(ids[i] + 1),
			Priority: uint16(1 + rng.Intn(1000)),
			Action:   ActionAllow,
		}
		if rng.Intn(2) == 0 {
			r.Action = ActionDeny
		}
		switch rng.Intn(4) {
		case 0:
			r.Proto = ProtoTCP
		case 1:
			r.Proto = ProtoUDP
		case 2:
			r.Proto = ProtoICMP
		case 3:
			r.Proto = ProtoAll
		}
		if r.Proto == ProtoTCP || r.Proto == ProtoUDP {
			lo := uint16(1 + rng.Intn(65535))
			hi := lo + uint16(rng.Intn(65536-int(lo)))
			r.Ports = pr(lo, hi)
		}
		bits := rng.Intn(33)
		addr := rng.Uint32() &^ uint32((uint64(1)<<(32-bits))-1)
		r.CIDR = fmt.Sprintf("%d.%d.%d.%d/%d", addr>>24, addr>>16&0xff, addr>>8&0xff, addr&0xff, bits)
		rules = append(rules, r)
	}
	return rules
}

func BenchmarkAnalyze200(b *testing.B) {
	set, err := NewRuleSet(genWideRules(rand.New(rand.NewSource(1)), 200))
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Analyze(set)
	}
}

func BenchmarkEquivalent200(b *testing.B) {
	a, err := NewRuleSet(genWideRules(rand.New(rand.NewSource(1)), 200))
	if err != nil {
		b.Fatal(err)
	}
	bs, err := NewRuleSet(genWideRules(rand.New(rand.NewSource(2)), 200))
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Equivalent(a, bs)
	}
}

// Worst case for Equivalent: semantically equal sets force a full scan.
func BenchmarkEquivalent200FullScan(b *testing.B) {
	rules := genWideRules(rand.New(rand.NewSource(1)), 200)
	a, err := NewRuleSet(rules)
	if err != nil {
		b.Fatal(err)
	}
	rev := make([]Rule, len(rules))
	for i, r := range rules {
		rev[len(rules)-1-i] = r
	}
	bs, err := NewRuleSet(rev)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !Equivalent(a, bs).Equivalent {
			b.Fatal("should be equivalent")
		}
	}
}
