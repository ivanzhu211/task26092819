package sgrules

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
)

// MaxRules is the maximum number of rules in a set.
const MaxRules = 200

// normRule is a rule normalized into integer intervals for fast matching.
type normRule struct {
	id       int
	priority int
	proto    Protocol
	portLo   uint32 // valid for tcp/udp spaces
	portHi   uint32
	addrLo   uint32
	addrHi   uint32
	action   Action
}

// RuleSet is a validated, match-ordered set of rules for one direction.
type RuleSet struct {
	rules []normRule // sorted by match order
}

// NewRuleSet validates rules and builds a RuleSet.
func NewRuleSet(rules []Rule) (*RuleSet, error) {
	if len(rules) > MaxRules {
		return nil, fmt.Errorf("sgrules: %d rules exceeds maximum of %d", len(rules), MaxRules)
	}
	seen := make(map[int]struct{}, len(rules))
	normed := make([]normRule, 0, len(rules))
	for i := range rules {
		r := rules[i]
		if r.ID < 1 {
			return nil, fmt.Errorf("sgrules: rule ID %d is not a positive integer", r.ID)
		}
		if _, dup := seen[r.ID]; dup {
			return nil, fmt.Errorf("sgrules: duplicate rule ID %d", r.ID)
		}
		seen[r.ID] = struct{}{}
		if r.Priority < 1 || r.Priority > 1000 {
			return nil, fmt.Errorf("sgrules: rule %d: priority %d out of range [1,1000]", r.ID, r.Priority)
		}
		switch r.Protocol {
		case ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolAll:
		default:
			return nil, fmt.Errorf("sgrules: rule %d: invalid protocol %q", r.ID, r.Protocol)
		}
		switch r.Action {
		case ActionAllow, ActionDeny:
		default:
			return nil, fmt.Errorf("sgrules: rule %d: invalid action %q", r.ID, r.Action)
		}
		nr := normRule{id: r.ID, priority: r.Priority, proto: r.Protocol, action: r.Action}
		switch r.Protocol {
		case ProtocolTCP, ProtocolUDP:
			if r.Ports == nil {
				return nil, fmt.Errorf("sgrules: rule %d: %s rule requires a port range", r.ID, r.Protocol)
			}
			if r.Ports.Lo < 1 || r.Ports.Lo > r.Ports.Hi {
				return nil, fmt.Errorf("sgrules: rule %d: invalid port range %d-%d", r.ID, r.Ports.Lo, r.Ports.Hi)
			}
			nr.portLo = uint32(r.Ports.Lo)
			nr.portHi = uint32(r.Ports.Hi)
		default:
			if r.Ports != nil {
				return nil, fmt.Errorf("sgrules: rule %d: %s rule must not have a port range", r.ID, r.Protocol)
			}
		}
		prefix, err := netip.ParsePrefix(r.CIDR)
		if err != nil {
			return nil, fmt.Errorf("sgrules: rule %d: invalid CIDR %q: %w", r.ID, r.CIDR, err)
		}
		if !prefix.Addr().Is4() {
			return nil, fmt.Errorf("sgrules: rule %d: CIDR %q is not an IPv4 prefix", r.ID, r.CIDR)
		}
		if prefix.Masked() != prefix {
			return nil, fmt.Errorf("sgrules: rule %d: CIDR %q has non-zero host bits", r.ID, r.CIDR)
		}
		nr.addrLo = addr4ToUint32(prefix.Addr())
		nr.addrHi = nr.addrLo + (uint32(1)<<(32-prefix.Bits()) - 1)
		normed = append(normed, nr)
	}
	sort.SliceStable(normed, func(i, j int) bool {
		a, b := normed[i], normed[j]
		if a.priority != b.priority {
			return a.priority < b.priority
		}
		if a.action != b.action {
			return a.action == ActionDeny // deny before allow on tie
		}
		return a.id < b.id
	})
	return &RuleSet{rules: normed}, nil
}

func addr4ToUint32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

var errInvalidPacket = errors.New("sgrules: invalid packet")
