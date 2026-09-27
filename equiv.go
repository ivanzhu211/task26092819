package sgrules

// Equivalent reports whether two rule sets decide every packet identically.
// When they differ, it returns a witness packet on which the actions differ.
func Equivalent(a, b *RuleSet) (bool, *Packet) {
	for _, sp := range spaces() {
		rulesA := a.project(sp)
		rulesB := b.project(sp)
		if len(rulesA) == 0 && len(rulesB) == 0 {
			continue
		}
		addrBounds := []uint64{0, 1 << 32}
		for _, r := range rulesA {
			addrBounds = append(addrBounds, uint64(r.addrLo), uint64(r.addrHi)+1)
		}
		for _, r := range rulesB {
			addrBounds = append(addrBounds, uint64(r.addrLo), uint64(r.addrHi)+1)
		}
		addrBounds = uniqSorted(addrBounds)
		for ai := 0; ai+1 < len(addrBounds); ai++ {
			aLo := uint32(addrBounds[ai])
			coverA := covering(rulesA, aLo)
			coverB := covering(rulesB, aLo)
			if len(coverA) == 0 && len(coverB) == 0 {
				continue
			}
			portBounds := []uint64{uint64(sp.spacePortLo), uint64(sp.spacePortHi) + 1}
			for _, r := range coverA {
				portBounds = append(portBounds, uint64(r.portLo), uint64(r.portHi)+1)
			}
			for _, r := range coverB {
				portBounds = append(portBounds, uint64(r.portLo), uint64(r.portHi)+1)
			}
			portBounds = uniqSorted(portBounds)
			for pi := 0; pi+1 < len(portBounds); pi++ {
				pLo := uint32(portBounds[pi])
				actA := firstAction(a, coverA, pLo)
				actB := firstAction(b, coverB, pLo)
				if actA != actB {
					w := Packet{
						Protocol: sp.proto,
						Port:     uint16(pLo),
						Addr:     uint32ToAddr4(aLo),
					}
					return false, &w
				}
			}
		}
	}
	return true, nil
}

func covering(rules []spaceRule, addrLo uint32) []spaceRule {
	var out []spaceRule
	for _, r := range rules {
		if r.addrLo <= addrLo && addrLo <= r.addrHi {
			out = append(out, r)
		}
	}
	return out
}

// firstAction returns the action of the first covering rule (in match order)
// whose port range contains pLo, or the default deny.
func firstAction(s *RuleSet, cover []spaceRule, pLo uint32) Action {
	for _, r := range cover {
		if r.portLo <= pLo && pLo <= r.portHi {
			return s.rules[r.idx].action
		}
	}
	return ActionDeny
}
