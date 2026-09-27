package sgrules

import "sort"

// interval is a closed uint64 interval. uint64 is used so that the upper
// bound of "0.0.0.0/0" (2^32-1) and port 65535 never overflow.
type interval struct{ lo, hi uint64 }

// atomicIntervals partitions [fullLo, fullHi] into the coarsest intervals
// that never cross any boundary of ivls. Every ivl must lie inside
// [fullLo, fullHi]. The result covers [fullLo, fullHi] completely.
func atomicIntervals(ivls []interval, fullLo, fullHi uint64) []interval {
	bounds := []uint64{fullLo, fullHi + 1}
	for _, iv := range ivls {
		if iv.lo > fullLo {
			bounds = append(bounds, iv.lo)
		}
		if iv.hi+1 < fullHi+1 {
			bounds = append(bounds, iv.hi+1)
		}
	}
	sort.Slice(bounds, func(i, j int) bool { return bounds[i] < bounds[j] })
	out := make([]interval, 0, len(bounds))
	prev := bounds[0]
	for _, b := range bounds[1:] {
		if b == prev {
			continue
		}
		out = append(out, interval{lo: prev, hi: b - 1})
		prev = b
	}
	return out
}

// cellSpace is the product decomposition of the packet space used for exact
// analysis. Because intervals are atomic w.r.t. every rule's CIDR and port
// range, each rule either fully covers or fully misses a cell, so checking
// the cell's representative point decides the whole cell.
type cellSpace struct {
	addrIvls []interval // partition of [0, 2^32-1]
	portIvls []interval // partition of [1, 65535]
}

func newCellSpace(sets ...*RuleSet) cellSpace {
	var addrIvls, portIvls []interval
	for _, s := range sets {
		for i := range s.rules {
			lo, hi := cidrBounds(s.cidrs[i])
			addrIvls = append(addrIvls, interval{lo: uint64(lo), hi: uint64(hi)})
			if p := s.rules[i].Ports; p != nil {
				portIvls = append(portIvls, interval{lo: uint64(p.Lo), hi: uint64(p.Hi)})
			}
		}
	}
	return cellSpace{
		addrIvls: atomicIntervals(addrIvls, 0, 1<<32-1),
		portIvls: atomicIntervals(portIvls, 1, 65535),
	}
}

// forEachCell calls fn once per atomic cell with a representative packet
// point: every (proto, port, addr) triple inside the cell behaves
// identically under every rule of the sets the space was built from.
// icmp cells use port 0 (icmp packets carry no port).
func (cs cellSpace) forEachCell(fn func(proto Protocol, port uint32, addr uint32)) {
	for _, ai := range cs.addrIvls {
		addr := uint32(ai.lo)
		for _, pi := range cs.portIvls {
			port := uint32(pi.lo)
			fn(ProtoTCP, port, addr)
			fn(ProtoUDP, port, addr)
		}
		fn(ProtoICMP, 0, addr)
	}
}

// compiledRule is a rule flattened to plain integer ranges for fast
// per-cell matching.
type compiledRule struct {
	proto          Protocol
	portLo, portHi uint32 // meaningful only for tcp/udp rules
	addrLo, addrHi uint32
	action         Action
}

func compileSet(s *RuleSet) []compiledRule {
	out := make([]compiledRule, len(s.rules))
	for i, r := range s.rules {
		cr := compiledRule{proto: r.Proto, action: r.Action}
		if r.Ports != nil {
			cr.portLo, cr.portHi = uint32(r.Ports.Lo), uint32(r.Ports.Hi)
		}
		cr.addrLo, cr.addrHi = cidrBounds(s.cidrs[i])
		out[i] = cr
	}
	return out
}

// matches reports whether the compiled rule matches the given packet point.
func (cr compiledRule) matches(proto Protocol, port, addr uint32) bool {
	switch cr.proto {
	case ProtoTCP, ProtoUDP:
		if proto != cr.proto || port < cr.portLo || port > cr.portHi {
			return false
		}
	case ProtoICMP:
		if proto != ProtoICMP {
			return false
		}
		// case ProtoAll: matches every protocol, no port constraint
	}
	return addr >= cr.addrLo && addr <= cr.addrHi
}

// firstHit returns the index of the first compiled rule matching the point,
// or -1. If skip >= 0, that rule index is ignored (used to evaluate the
// "rule deleted" scenario).
func firstHit(rules []compiledRule, skip int, proto Protocol, port, addr uint32) int {
	for i := range rules {
		if i == skip {
			continue
		}
		if rules[i].matches(proto, port, addr) {
			return i
		}
	}
	return -1
}

// actionAt returns the action the compiled rules decide for the point,
// with skip interpreted as in firstHit. Default is deny.
func actionAt(rules []compiledRule, skip int, proto Protocol, port, addr uint32) Action {
	if i := firstHit(rules, skip, proto, port, addr); i >= 0 {
		return rules[i].action
	}
	return ActionDeny
}
