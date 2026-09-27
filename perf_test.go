package sgrules

import (
	"math/rand"
	"net/netip"
	"testing"
	"time"
)

// bigRuleSet builds n rules with wide, heavily overlapping ranges.
func bigRuleSet(rng *rand.Rand, n int) []Rule {
	rules := make([]Rule, 0, n)
	for i := 1; i <= n; i++ {
		r := Rule{
			ID:       i,
			Priority: 1 + rng.Intn(1000),
			Action:   []Action{ActionAllow, ActionDeny}[rng.Intn(2)],
		}
		// random IPv4 prefix, biased to wide ranges so overlaps are common
		v := rng.Uint32()
		bits := rng.Intn(33)
		if rng.Intn(2) == 0 {
			bits = rng.Intn(9) // /0../8
		}
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}), bits).Masked()
		r.CIDR = p.String()
		switch rng.Intn(6) {
		case 0, 1:
			r.Protocol = ProtocolTCP
		case 2, 3:
			r.Protocol = ProtocolUDP
		case 4:
			r.Protocol = ProtocolICMP
		default:
			r.Protocol = ProtocolAll
		}
		if r.Protocol == ProtocolTCP || r.Protocol == ProtocolUDP {
			lo := uint16(1 + rng.Intn(65535))
			hi := lo
			if rng.Intn(2) == 0 {
				hi = 65535
			} else {
				hi = lo + uint16(rng.Intn(1+int(65535-lo)))
			}
			r.Ports = &PortRange{lo, hi}
		}
		rules = append(rules, r)
	}
	return rules
}

// nestedRuleSet is adversarial for the cell decomposition: every rule's
// CIDR contains the next, so cover lists stay long at every row.
func nestedRuleSet(n int) []Rule {
	rules := make([]Rule, 0, n)
	for i := 1; i <= n; i++ {
		bits := (i - 1) * 32 / n // /0, /0, ..., /31 spread
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, 0, 0}), bits).Masked()
		rules = append(rules, Rule{
			ID:       i,
			Priority: i,
			Protocol: ProtocolTCP,
			Ports:    &PortRange{uint16(1 + (i-1)*65534/n), 65535},
			CIDR:     p.String(),
			Action:   []Action{ActionAllow, ActionDeny}[i%2],
		})
	}
	return rules
}

func TestPerfAnalyze200(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for _, rules := range [][]Rule{bigRuleSet(rng, 200), nestedRuleSet(200)} {
		s := mustSet(t, rules)
		start := time.Now()
		res := Analyze(s)
		d := time.Since(start)
		t.Logf("Analyze(200 rules) took %v", d)
		if d > time.Second {
			t.Fatalf("Analyze too slow: %v", d)
		}
		if len(res) != 200 {
			t.Fatalf("got %d results", len(res))
		}
	}
}

func TestPerfEquivalent200x200(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	a := mustSet(t, bigRuleSet(rng, 200))
	b := mustSet(t, bigRuleSet(rng, 200))
	start := time.Now()
	eq, w := Equivalent(a, b)
	d := time.Since(start)
	t.Logf("Equivalent(200x200 random) took %v (eq=%v)", d, eq)
	if d > time.Second {
		t.Fatalf("Equivalent too slow: %v", d)
	}
	if !eq && w != nil {
		actA, _, _ := Evaluate(a, *w)
		actB, _, _ := Evaluate(b, *w)
		if actA == actB {
			t.Fatal("witness actions equal")
		}
	}
	// Equivalent pair: both allow-all at top, differing only in shadowed
	// rules below -> full scan, no early exit.
	full := []Rule{{ID: 1001, Priority: 1, Protocol: ProtocolAll, CIDR: "0.0.0.0/0", Action: ActionAllow}}
	full = append(full, bigRuleSet(rng, 199)...)
	full2 := []Rule{{ID: 1002, Priority: 1, Protocol: ProtocolAll, CIDR: "0.0.0.0/0", Action: ActionAllow}}
	full2 = append(full2, bigRuleSet(rng, 199)...)
	s1, s2 := mustSet(t, full), mustSet(t, full2)
	start = time.Now()
	eq, _ = Equivalent(s1, s2)
	d = time.Since(start)
	t.Logf("Equivalent(200x200 equivalent, full scan) took %v (eq=%v)", d, eq)
	if !eq {
		t.Fatal("expected equivalent")
	}
	if d > time.Second {
		t.Fatalf("Equivalent full scan too slow: %v", d)
	}
}
