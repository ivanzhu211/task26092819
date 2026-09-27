package sgrules

import (
	"math/rand"
	"net/netip"
	"sort"
	"testing"
)

// ---- reference implementation (test-only, point-by-point exhaustive) ----

type refRule struct {
	r              Rule
	addrLo, addrHi uint32
	portLo, portHi uint32
}

func buildRef(t *testing.T, rules []Rule) []refRule {
	t.Helper()
	out := make([]refRule, 0, len(rules))
	for _, r := range rules {
		p := netip.MustParsePrefix(r.CIDR)
		rr := refRule{r: r, addrLo: addr4ToUint32(p.Addr())}
		rr.addrHi = rr.addrLo + (uint32(1)<<(32-p.Bits()) - 1)
		if r.Ports != nil {
			rr.portLo = uint32(r.Ports.Lo)
			rr.portHi = uint32(r.Ports.Hi)
		}
		out = append(out, rr)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i].r, out[j].r
		if a.Priority != b.Priority {
			return a.Priority < b.Priority
		}
		if a.Action != b.Action {
			return a.Action == ActionDeny
		}
		return a.ID < b.ID
	})
	return out
}

func refMatch(rr *refRule, proto Protocol, port, addr uint32) bool {
	if addr < rr.addrLo || addr > rr.addrHi {
		return false
	}
	if rr.r.Protocol != ProtocolAll && rr.r.Protocol != proto {
		return false
	}
	if rr.r.Protocol == ProtocolTCP || rr.r.Protocol == ProtocolUDP {
		if port < rr.portLo || port > rr.portHi {
			return false
		}
	}
	return true
}

// refFirstTwo returns the first two rules (in match order) hitting the packet.
func refFirstTwo(rules []refRule, proto Protocol, port, addr uint32) (int, int) {
	first, second := -1, -1
	for i := range rules {
		if refMatch(&rules[i], proto, port, addr) {
			if first < 0 {
				first = i
			} else {
				second = i
				break
			}
		}
	}
	return first, second
}

// sampleSpace builds a packet sample that is exhaustive over a small range
// (all of 10.0.0.0/24, ports 1..512) and additionally contains every cell
// corner induced by the given rules, plus points outside the small range.
func sampleSpace(ruleSets ...[]Rule) (addrs []uint32, ports []uint32) {
	addrSet := map[uint32]struct{}{}
	for v := uint32(0); v < 256; v++ {
		addrSet[0x0a000000+v] = struct{}{} // 10.0.0.0/24 exhaustive
	}
	for _, a := range []uint32{0, 0x01010101, 0x09ffffff, 0x0a000100, 0x0a0001ff, 0xac100001, 0xc0a80101, 0xffffffff} {
		addrSet[a] = struct{}{}
	}
	portSet := map[uint32]struct{}{}
	for p := uint32(1); p <= 512; p++ {
		portSet[p] = struct{}{}
	}
	portSet[65535] = struct{}{}
	for _, rules := range ruleSets {
		for _, r := range rules {
			p := netip.MustParsePrefix(r.CIDR)
			lo := addr4ToUint32(p.Addr())
			hi := lo + (uint32(1)<<(32-p.Bits()) - 1)
			addrSet[lo] = struct{}{}
			addrSet[hi] = struct{}{}
			if lo > 0 {
				addrSet[lo-1] = struct{}{}
			}
			if hi < 0xffffffff {
				addrSet[hi+1] = struct{}{}
			}
			if r.Ports != nil {
				plo, phi := uint32(r.Ports.Lo), uint32(r.Ports.Hi)
				portSet[plo] = struct{}{}
				portSet[phi] = struct{}{}
				if plo > 1 {
					portSet[plo-1] = struct{}{}
				}
				if phi < 65535 {
					portSet[phi+1] = struct{}{}
				}
			}
		}
	}
	for a := range addrSet {
		addrs = append(addrs, a)
	}
	for p := range portSet {
		ports = append(ports, p)
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i] < addrs[j] })
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	return addrs, ports
}

func eachPacket(addrs, ports []uint32, fn func(proto Protocol, port, addr uint32)) {
	for _, proto := range []Protocol{ProtocolTCP, ProtocolUDP} {
		for _, addr := range addrs {
			for _, port := range ports {
				fn(proto, port, addr)
			}
		}
	}
	for _, addr := range addrs {
		fn(ProtocolICMP, 0, addr)
	}
}

// ---- random rule generation ----

var cidrPool = []string{
	"0.0.0.0/0", "0.0.0.0/32", "10.0.0.0/24", "10.0.0.0/25", "10.0.0.128/25",
	"10.0.0.0/28", "10.0.0.16/28", "10.0.0.32/27", "10.0.0.64/26",
	"10.0.0.128/26", "10.0.0.192/26", "10.0.0.0/23", "10.0.0.0/16",
	"10.0.1.7/32", "255.255.255.255/32", "192.168.0.0/16", "1.1.1.1/32",
}

var portPool = []PortRange{
	{1, 65535}, {80, 80}, {443, 443}, {53, 53}, {1024, 2048},
	{8080, 8080}, {65535, 65535}, {1, 512}, {1, 1}, {512, 512},
}

func randCIDR(rng *rand.Rand) string {
	if rng.Intn(3) == 0 {
		// random prefix inside 10.0.0.0/16
		v := 0x0a000000 + uint32(rng.Intn(1<<16))
		bits := 16 + rng.Intn(17)
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}), bits).Masked()
		return p.String()
	}
	return cidrPool[rng.Intn(len(cidrPool))]
}

func randPorts(rng *rand.Rand) *PortRange {
	if rng.Intn(3) == 0 {
		lo := uint16(1 + rng.Intn(2000))
		hi := lo + uint16(rng.Intn(1+int(65535-lo)))
		return &PortRange{lo, hi}
	}
	p := portPool[rng.Intn(len(portPool))]
	return &PortRange{p.Lo, p.Hi}
}

func randRuleSet(rng *rand.Rand, n int) []Rule {
	rules := make([]Rule, 0, n)
	for i := 1; i <= n; i++ {
		r := Rule{
			ID:       i,
			Priority: 1 + rng.Intn(5),
			Action:   []Action{ActionAllow, ActionDeny}[rng.Intn(2)],
			CIDR:     randCIDR(rng),
		}
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
			r.Ports = randPorts(rng)
		}
		rules = append(rules, r)
	}
	return rules
}

// ---- differential tests ----

func TestAnalyzeDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(20260928))
	for iter := 0; iter < 150; iter++ {
		rules := randRuleSet(rng, 1+rng.Intn(12))
		s := mustSet(t, rules)
		ref := buildRef(t, rules)
		addrs, ports := sampleSpace(rules)

		firstHit := map[int]bool{}
		flips := map[int]bool{}
		eachPacket(addrs, ports, func(proto Protocol, port, addr uint32) {
			first, second := refFirstTwo(ref, proto, port, addr)
			if first < 0 {
				return
			}
			id := ref[first].r.ID
			firstHit[id] = true
			fallback := ActionDeny
			if second >= 0 {
				fallback = ref[second].r.Action
			}
			if fallback != ref[first].r.Action {
				flips[id] = true
			}
		})

		for _, ra := range Analyze(s) {
			want := Shadowed
			if firstHit[ra.RuleID] {
				if flips[ra.RuleID] {
					want = Effective
				} else {
					want = Redundant
				}
			}
			if ra.Class != want {
				t.Fatalf("iter %d rule %d: got %v want %v (rules=%v)", iter, ra.RuleID, ra.Class, want, rules)
			}
			if ra.Class == Effective {
				w := ra.Witness
				// witness must be first-hit by this rule in the reference
				var wp uint32
				if w.Protocol != ProtocolICMP {
					wp = uint32(w.Port)
				}
				first, second := refFirstTwo(ref, w.Protocol, wp, addr4ToUint32(w.Addr))
				if first < 0 || ref[first].r.ID != ra.RuleID {
					t.Fatalf("iter %d rule %d: witness not first-hit (rules=%v)", iter, ra.RuleID, rules)
				}
				fallback := ActionDeny
				if second >= 0 {
					fallback = ref[second].r.Action
				}
				if fallback == ref[first].r.Action {
					t.Fatalf("iter %d rule %d: witness does not flip (rules=%v)", iter, ra.RuleID, rules)
				}
				// and Evaluate must agree with the reference on the witness
				act, id, err := Evaluate(s, *w)
				if err != nil || id != ra.RuleID || act != ref[first].r.Action {
					t.Fatalf("iter %d rule %d: Evaluate(witness)=%v,%d,%v", iter, ra.RuleID, act, id, err)
				}
			}
		}
	}
}

func TestEquivalentDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for iter := 0; iter < 150; iter++ {
		rulesA := randRuleSet(rng, 1+rng.Intn(10))
		var rulesB []Rule
		if rng.Intn(2) == 0 {
			// mutate A: drop a rule, tweak priorities, maybe add one
			for _, r := range rulesA {
				if rng.Intn(4) == 0 {
					continue
				}
				r.Priority = 1 + rng.Intn(5)
				rulesB = append(rulesB, r)
			}
			if rng.Intn(2) == 0 {
				extra := randRuleSet(rng, 1)
				extra[0].ID = 1000 + iter
				rulesB = append(rulesB, extra...)
			}
		} else {
			rulesB = randRuleSet(rng, 1+rng.Intn(10))
		}
		a, b := mustSet(t, rulesA), mustSet(t, rulesB)
		refA, refB := buildRef(t, rulesA), buildRef(t, rulesB)
		addrs, ports := sampleSpace(rulesA, rulesB)

		refEq := true
		var refWit *Packet
		eachPacket(addrs, ports, func(proto Protocol, port, addr uint32) {
			if !refEq {
				return
			}
			fa, _ := refFirstTwo(refA, proto, port, addr)
			fb, _ := refFirstTwo(refB, proto, port, addr)
			actA, actB := ActionDeny, ActionDeny
			if fa >= 0 {
				actA = refA[fa].r.Action
			}
			if fb >= 0 {
				actB = refB[fb].r.Action
			}
			if actA != actB {
				refEq = false
				p := Packet{Protocol: proto, Port: uint16(port), Addr: uint32ToAddr4(addr)}
				refWit = &p
			}
		})

		eq, w := Equivalent(a, b)
		if eq != refEq {
			t.Fatalf("iter %d: Equivalent=%v, reference=%v (refWit=%+v)\nA=%v\nB=%v", iter, eq, refEq, refWit, rulesA, rulesB)
		}
		if !eq {
			if w == nil {
				t.Fatalf("iter %d: non-equivalent without witness", iter)
			}
			actA, _, err := Evaluate(a, *w)
			if err != nil {
				t.Fatalf("iter %d: witness not evaluable: %v", iter, err)
			}
			actB, _, _ := Evaluate(b, *w)
			if actA == actB {
				t.Fatalf("iter %d: witness actions equal (%v)", iter, actA)
			}
		}
	}
}
