package sgrules

import (
	"fmt"
	"math/rand"
	"net/netip"
	"sort"
	"testing"
)

// This file holds a test-only, point-by-point exhaustive reference
// implementation. It shares no code with the library's analysis engine:
// it builds its own atomic partition of the WHOLE packet space (including
// addresses and ports outside the generator's small range) and evaluates
// real sample points of every atomic region with a naive per-rule matcher.

type refPoint struct {
	proto Protocol
	port  uint32
	addr  uint32
}

type refInterval struct{ lo, hi uint64 }

// refAtomic partitions [fullLo, fullHi] around the given boundaries.
func refAtomic(ivls []refInterval, fullLo, fullHi uint64) []refInterval {
	set := map[uint64]bool{fullLo: true, fullHi + 1: true}
	for _, iv := range ivls {
		if iv.lo > fullLo {
			set[iv.lo] = true
		}
		if iv.hi+1 < fullHi+1 {
			set[iv.hi+1] = true
		}
	}
	bounds := make([]uint64, 0, len(set))
	for b := range set {
		bounds = append(bounds, b)
	}
	sort.Slice(bounds, func(i, j int) bool { return bounds[i] < bounds[j] })
	var out []refInterval
	for i := 0; i+1 < len(bounds); i++ {
		out = append(out, refInterval{lo: bounds[i], hi: bounds[i+1] - 1})
	}
	return out
}

func refCIDRBounds(t *testing.T, cidr string) refInterval {
	t.Helper()
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		t.Fatalf("bad cidr %q: %v", cidr, err)
	}
	a := p.Addr().As4()
	lo := uint64(a[0])<<24 | uint64(a[1])<<16 | uint64(a[2])<<8 | uint64(a[3])
	size := uint64(1) << (32 - p.Bits())
	return refInterval{lo: lo, hi: lo + size - 1}
}

// refPoints enumerates sample points (lo, mid, hi) of every atomic region
// of the full packet space induced by the given rules.
func refPoints(t *testing.T, ruleLists ...[]Rule) []refPoint {
	t.Helper()
	var addrIvls, portIvls []refInterval
	for _, rules := range ruleLists {
		for _, r := range rules {
			addrIvls = append(addrIvls, refCIDRBounds(t, r.CIDR))
			if r.Ports != nil {
				portIvls = append(portIvls, refInterval{lo: uint64(r.Ports.Lo), hi: uint64(r.Ports.Hi)})
			}
		}
	}
	addrs := refAtomic(addrIvls, 0, 1<<32-1)
	ports := refAtomic(portIvls, 1, 65535)

	samples := func(iv refInterval) []uint64 {
		mid := iv.lo/2 + iv.hi/2 + (iv.lo&1+iv.hi&1)/2 // overflow-safe midpoint
		if iv.lo == iv.hi {
			return []uint64{iv.lo}
		}
		return []uint64{iv.lo, mid, iv.hi}
	}
	var pts []refPoint
	for _, ai := range addrs {
		for _, av := range samples(ai) {
			for _, pi := range ports {
				for _, pv := range samples(pi) {
					pts = append(pts,
						refPoint{proto: ProtoTCP, port: uint32(pv), addr: uint32(av)},
						refPoint{proto: ProtoUDP, port: uint32(pv), addr: uint32(av)})
				}
			}
			pts = append(pts, refPoint{proto: ProtoICMP, port: 0, addr: uint32(av)})
		}
	}
	return pts
}

// refSort orders rules by (priority asc, deny before allow, ID asc).
func refSort(rules []Rule) []Rule {
	out := make([]Rule, len(rules))
	copy(out, rules)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
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

func refMatch(t *testing.T, r Rule, pt refPoint) bool {
	t.Helper()
	switch r.Proto {
	case ProtoTCP, ProtoUDP:
		if pt.proto != r.Proto || pt.port < uint32(r.Ports.Lo) || pt.port > uint32(r.Ports.Hi) {
			return false
		}
	case ProtoICMP:
		if pt.proto != ProtoICMP {
			return false
		}
	case ProtoAll:
	default:
		t.Fatalf("unexpected proto %q", r.Proto)
	}
	p, err := netip.ParsePrefix(r.CIDR)
	if err != nil {
		t.Fatalf("bad cidr: %v", err)
	}
	addr := netip.AddrFrom4([4]byte{byte(pt.addr >> 24), byte(pt.addr >> 16), byte(pt.addr >> 8), byte(pt.addr)})
	return p.Contains(addr)
}

// refAction evaluates the naive first-hit semantics at one point, with
// rule index skip (in sorted order) treated as deleted (-1: none).
func refAction(t *testing.T, sorted []Rule, skip int, pt refPoint) Action {
	t.Helper()
	for i, r := range sorted {
		if i == skip {
			continue
		}
		if refMatch(t, r, pt) {
			return r.Action
		}
	}
	return ActionDeny
}

func refAnalyze(t *testing.T, rules []Rule) map[uint32]Classification {
	t.Helper()
	sorted := refSort(rules)
	hit := make([]bool, len(sorted))
	flip := make([]bool, len(sorted))
	for _, pt := range refPoints(t, rules) {
		first := -1
		for i, r := range sorted {
			if refMatch(t, r, pt) {
				first = i
				break
			}
		}
		if first < 0 {
			continue
		}
		hit[first] = true
		if !flip[first] && refAction(t, sorted, first, pt) != sorted[first].Action {
			flip[first] = true
		}
	}
	out := make(map[uint32]Classification, len(sorted))
	for i, r := range sorted {
		switch {
		case !hit[i]:
			out[r.ID] = Shadowed
		case !flip[i]:
			out[r.ID] = Redundant
		default:
			out[r.ID] = Effective
		}
	}
	return out
}

func refEquivalent(t *testing.T, a, b []Rule) (bool, *refPoint) {
	t.Helper()
	sa, sb := refSort(a), refSort(b)
	for _, pt := range refPoints(t, a, b) {
		if refAction(t, sa, -1, pt) != refAction(t, sb, -1, pt) {
			p := pt
			return false, &p
		}
	}
	return true, nil
}

// --- generator: small-range CIDRs/ports mixed with 0.0.0.0/0, full port
// ranges, icmp and all rules ---

func genCIDR(rng *rand.Rand) string {
	switch rng.Intn(10) {
	case 0, 1:
		return "0.0.0.0/0"
	case 2:
		return "10.0.0.0/24"
	case 3:
		return "10.0.0.0/8"
	default:
		bits := 28 + rng.Intn(5) // /28../32 inside 10.0.0.0/28
		block := 1 << (32 - bits)
		offset := rng.Intn(16/block) * block
		return fmt.Sprintf("10.0.0.%d/%d", offset, bits)
	}
}

func genRules(rng *rand.Rand, n int) []Rule {
	ids := rng.Perm(n)
	rules := make([]Rule, 0, n)
	for i := 0; i < n; i++ {
		r := Rule{
			ID:       uint32(ids[i] + 1),
			Priority: uint16(1 + rng.Intn(6)),
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
			if rng.Intn(4) == 0 {
				r.Ports = pr(1, 65535)
			} else {
				lo := uint16(1 + rng.Intn(8))
				hi := lo + uint16(rng.Intn(int(9-lo)))
				r.Ports = pr(lo, hi)
			}
		}
		r.CIDR = genCIDR(rng)
		rules = append(rules, r)
	}
	return rules
}

func TestDifferentialAnalyze(t *testing.T) {
	for seed := int64(0); seed < 200; seed++ {
		rng := rand.New(rand.NewSource(seed))
		rules := genRules(rng, 2+rng.Intn(11))
		set, err := NewRuleSet(rules)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		want := refAnalyze(t, rules)
		for _, ra := range Analyze(set) {
			if got := ra.Class; got != want[ra.RuleID] {
				t.Fatalf("seed %d: rule %d: got class %v, reference says %v (rules=%+v)", seed, ra.RuleID, got, want[ra.RuleID], rules)
			}
		}
		checkWitnesses(t, set)
	}
}

func TestDifferentialEquivalent(t *testing.T) {
	for seed := int64(0); seed < 200; seed++ {
		rng := rand.New(rand.NewSource(seed))
		rulesA := genRules(rng, 2+rng.Intn(10))
		var rulesB []Rule
		if rng.Intn(2) == 0 {
			rulesB = genRules(rng, 2+rng.Intn(10))
		} else {
			// Mutate A: near-equivalent pairs exercise the tight cases.
			rulesB = make([]Rule, len(rulesA))
			copy(rulesB, rulesA)
			switch rng.Intn(3) {
			case 0: // drop a rule
				i := rng.Intn(len(rulesB))
				rulesB = append(rulesB[:i], rulesB[i+1:]...)
			case 1: // flip an action
				i := rng.Intn(len(rulesB))
				if rulesB[i].Action == ActionAllow {
					rulesB[i].Action = ActionDeny
				} else {
					rulesB[i].Action = ActionAllow
				}
			case 2: // tweak a port range
				for i := range rulesB {
					if rulesB[i].Ports != nil {
						p := *rulesB[i].Ports
						if p.Hi < 65535 {
							p.Hi++
						} else {
							p.Lo++
						}
						if p.Lo >= 1 && p.Lo <= p.Hi {
							rulesB[i].Ports = &p
						}
						break
					}
				}
			}
		}
		a, err := NewRuleSet(rulesA)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		b, err := NewRuleSet(rulesB)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		wantEq, wantPt := refEquivalent(t, rulesA, rulesB)
		got := Equivalent(a, b)
		if got.Equivalent != wantEq {
			t.Fatalf("seed %d: Equivalent=%v, reference says %v", seed, got.Equivalent, wantEq)
		}
		if wantEq {
			continue
		}
		if got.Witness == nil {
			t.Fatalf("seed %d: non-equivalent but no witness", seed)
		}
		// The witness must be a valid, correctly-classified packet.
		w := *got.Witness
		actA, _ := Evaluate(a, w)
		actB, _ := Evaluate(b, w)
		if actA == actB {
			t.Fatalf("seed %d: witness %+v decides %s on both sets", seed, w, actA)
		}
		// Cross-check against the reference's own differing point.
		if wantPt != nil {
			rp := Packet{Proto: wantPt.proto, Port: uint16(wantPt.port), Addr: wantPt.addr}
			ra, _ := Evaluate(a, rp)
			rb, _ := Evaluate(b, rp)
			if ra == rb {
				t.Fatalf("seed %d: reference point %+v agrees under Evaluate", seed, rp)
			}
		}
	}
}
