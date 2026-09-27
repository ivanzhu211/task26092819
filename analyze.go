package sgrules

import (
	"net/netip"
	"sort"
)

// spaceRule is a rule projected into one protocol's packet space.
type spaceRule struct {
	idx            int // index into RuleSet.rules (match order)
	portLo, portHi uint32
	addrLo, addrHi uint32
}

// packetSpace describes one protocol's packet universe.
type packetSpace struct {
	proto       Protocol
	spacePortLo uint32 // 1 for tcp/udp, 0 for icmp
	spacePortHi uint32 // 65535 for tcp/udp, 0 for icmp
}

func spaces() []packetSpace {
	return []packetSpace{
		{proto: ProtocolTCP, spacePortLo: 1, spacePortHi: 65535},
		{proto: ProtocolUDP, spacePortLo: 1, spacePortHi: 65535},
		{proto: ProtocolICMP, spacePortLo: 0, spacePortHi: 0},
	}
}

// project returns the rules matching this space, in match order, with port
// ranges mapped into the space's port domain.
func (s *RuleSet) project(sp packetSpace) []spaceRule {
	var out []spaceRule
	for i, r := range s.rules {
		sr := spaceRule{idx: i, addrLo: r.addrLo, addrHi: r.addrHi}
		switch r.proto {
		case sp.proto:
			if sp.proto == ProtocolICMP {
				sr.portLo, sr.portHi = 0, 0
			} else {
				sr.portLo, sr.portHi = r.portLo, r.portHi
			}
		case ProtocolAll:
			sr.portLo, sr.portHi = sp.spacePortLo, sp.spacePortHi
		default:
			continue
		}
		out = append(out, sr)
	}
	return out
}

// Analyze classifies every rule as Shadowed, Redundant or Effective.
// Results are returned in match order.
func Analyze(s *RuleSet) []RuleAnalysis {
	n := len(s.rules)
	firstHit := make([]bool, n)
	flips := make([]bool, n)     // exists a first-hit cell whose action flips without the rule
	witness := make([]Packet, n) // valid where flips is true
	for _, sp := range spaces() {
		srules := s.project(sp)
		if len(srules) == 0 {
			continue
		}
		addrBounds := []uint64{0, 1 << 32}
		for _, r := range srules {
			addrBounds = append(addrBounds, uint64(r.addrLo), uint64(r.addrHi)+1)
		}
		addrBounds = uniqSorted(addrBounds)
		for ai := 0; ai+1 < len(addrBounds); ai++ {
			aLo := uint32(addrBounds[ai])
			var cover []spaceRule
			for _, r := range srules {
				if r.addrLo <= aLo && aLo <= r.addrHi {
					cover = append(cover, r)
				}
			}
			if len(cover) == 0 {
				continue
			}
			portBounds := []uint64{uint64(sp.spacePortLo), uint64(sp.spacePortHi) + 1}
			for _, r := range cover {
				portBounds = append(portBounds, uint64(r.portLo), uint64(r.portHi)+1)
			}
			portBounds = uniqSorted(portBounds)
			for pi := 0; pi+1 < len(portBounds); pi++ {
				pLo := uint32(portBounds[pi])
				first, second := -1, -1
				for k := range cover {
					r := &cover[k]
					if r.portLo <= pLo && pLo <= r.portHi {
						if first < 0 {
							first = k
						} else {
							second = k
							break
						}
					}
				}
				if first < 0 {
					continue
				}
				fi := cover[first].idx
				firstHit[fi] = true
				// Action without the first-hit rule on this cell.
				fallback := ActionDeny
				if second >= 0 {
					fallback = s.rules[cover[second].idx].action
				}
				if fallback != s.rules[fi].action && !flips[fi] {
					flips[fi] = true
					witness[fi] = Packet{
						Protocol: sp.proto,
						Port:     uint16(pLo),
						Addr:     uint32ToAddr4(aLo),
					}
				}
			}
		}
	}
	out := make([]RuleAnalysis, n)
	for i, r := range s.rules {
		out[i].RuleID = r.id
		switch {
		case !firstHit[i]:
			out[i].Class = Shadowed
		case flips[i]:
			out[i].Class = Effective
			w := witness[i]
			out[i].Witness = &w
		default:
			out[i].Class = Redundant
		}
	}
	return out
}

func uniqSorted(v []uint64) []uint64 {
	sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
	out := v[:0]
	for i, x := range v {
		if i == 0 || x != v[i-1] {
			out = append(out, x)
		}
	}
	return out
}

func uint32ToAddr4(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}
