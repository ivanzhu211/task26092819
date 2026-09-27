package sgrules

import (
	"fmt"
	"net/netip"
	"sort"
)

// MaxRules is the maximum number of rules in a set.
const MaxRules = 200

// RuleSet is a validated, evaluation-ready set of rules for one direction.
type RuleSet struct {
	rules []Rule // sorted by (Priority asc, deny before allow, ID asc)
	cidrs []netip.Prefix
}

// NewRuleSet validates rules and builds a RuleSet.
func NewRuleSet(rules []Rule) (*RuleSet, error) {
	if len(rules) > MaxRules {
		return nil, fmt.Errorf("too many rules: %d > %d", len(rules), MaxRules)
	}
	seen := make(map[uint32]struct{}, len(rules))
	cidrs := make([]netip.Prefix, len(rules))
	for i, r := range rules {
		if r.ID == 0 {
			return nil, fmt.Errorf("rule %d: ID must be a positive integer", i)
		}
		if _, dup := seen[r.ID]; dup {
			return nil, fmt.Errorf("rule %d: duplicate ID %d", i, r.ID)
		}
		seen[r.ID] = struct{}{}
		if r.Priority < 1 || r.Priority > 1000 {
			return nil, fmt.Errorf("rule %d (ID %d): priority %d out of range [1,1000]", i, r.ID, r.Priority)
		}
		switch r.Proto {
		case ProtoTCP, ProtoUDP:
			if r.Ports == nil {
				return nil, fmt.Errorf("rule %d (ID %d): %s rule requires a port range", i, r.ID, r.Proto)
			}
			if r.Ports.Lo < 1 || r.Ports.Lo > r.Ports.Hi {
				return nil, fmt.Errorf("rule %d (ID %d): invalid port range [%d,%d]", i, r.ID, r.Ports.Lo, r.Ports.Hi)
			}
		case ProtoICMP, ProtoAll:
			if r.Ports != nil {
				return nil, fmt.Errorf("rule %d (ID %d): %s rule must not have a port range", i, r.ID, r.Proto)
			}
		default:
			return nil, fmt.Errorf("rule %d (ID %d): unknown protocol %q", i, r.ID, r.Proto)
		}
		if r.Action != ActionAllow && r.Action != ActionDeny {
			return nil, fmt.Errorf("rule %d (ID %d): unknown action %q", i, r.ID, r.Action)
		}
		p, err := netip.ParsePrefix(r.CIDR)
		if err != nil {
			return nil, fmt.Errorf("rule %d (ID %d): invalid CIDR %q: %w", i, r.ID, r.CIDR, err)
		}
		if !p.Addr().Is4() {
			return nil, fmt.Errorf("rule %d (ID %d): CIDR %q is not an IPv4 prefix", i, r.ID, r.CIDR)
		}
		if p != p.Masked() {
			return nil, fmt.Errorf("rule %d (ID %d): CIDR %q has non-zero host bits", i, r.ID, r.CIDR)
		}
		cidrs[i] = p
	}

	sorted := make([]Rule, len(rules))
	copy(sorted, rules)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if a.Priority != b.Priority {
			return a.Priority < b.Priority
		}
		if a.Action != b.Action {
			return a.Action == ActionDeny // deny before allow
		}
		return a.ID < b.ID
	})

	sortedCIDRs := make([]netip.Prefix, len(sorted))
	byID := make(map[uint32]netip.Prefix, len(rules))
	for j, orig := range rules {
		byID[orig.ID] = cidrs[j]
	}
	for i, r := range sorted {
		sortedCIDRs[i] = byID[r.ID]
	}
	return &RuleSet{rules: sorted, cidrs: sortedCIDRs}, nil
}

// Rules returns the sorted rules (defensive copy).
func (s *RuleSet) Rules() []Rule {
	out := make([]Rule, len(s.rules))
	copy(out, s.rules)
	return out
}

// cidrOf returns the parsed prefix of the i-th sorted rule.
func (s *RuleSet) cidrOf(i int) netip.Prefix { return s.cidrs[i] }

// cidrBounds returns the [lo, hi] IPv4 address bounds of p as uint32s.
// The arithmetic is done in uint64 so "0.0.0.0/0" yields hi = 2^32-1
// without overflow.
func cidrBounds(p netip.Prefix) (lo, hi uint32) {
	a := p.Addr().As4()
	base := uint64(a[0])<<24 | uint64(a[1])<<16 | uint64(a[2])<<8 | uint64(a[3])
	size := uint64(1) << (32 - p.Bits())
	return uint32(base), uint32(base + size - 1)
}

// ruleMatches reports whether sorted rule i matches pkt.
func (s *RuleSet) ruleMatches(i int, pkt Packet) bool {
	r := s.rules[i]
	switch r.Proto {
	case ProtoTCP, ProtoUDP:
		if pkt.Proto != r.Proto {
			return false
		}
		if pkt.Port < r.Ports.Lo || pkt.Port > r.Ports.Hi {
			return false
		}
	case ProtoICMP:
		if pkt.Proto != ProtoICMP {
			return false
		}
	case ProtoAll:
		if pkt.Proto != ProtoTCP && pkt.Proto != ProtoUDP && pkt.Proto != ProtoICMP {
			return false
		}
	}
	addr, ok := netip.AddrFromSlice([]byte{byte(pkt.Addr >> 24), byte(pkt.Addr >> 16), byte(pkt.Addr >> 8), byte(pkt.Addr)})
	if !ok {
		return false
	}
	return s.cidrs[i].Contains(addr)
}

// Evaluate returns the action decided for pkt and the ID of the deciding
// rule. When no rule matches, it returns (ActionDeny, 0).
func Evaluate(s *RuleSet, pkt Packet) (Action, uint32) {
	for i := range s.rules {
		if s.ruleMatches(i, pkt) {
			return s.rules[i].Action, s.rules[i].ID
		}
	}
	return ActionDeny, 0
}
