package sgrules

// Analyze classifies every rule of s as Shadowed, Redundant or Effective.
// Results are returned in the rule set's evaluation order.
//
// The analysis is exact: it reasons over the atomic cell decomposition of
// the whole packet space (all 2^32 addresses, all ports, all protocols),
// never over samples.
func Analyze(s *RuleSet) []RuleAnalysis {
	n := len(s.rules)
	results := make([]RuleAnalysis, n)
	for i, r := range s.rules {
		results[i].RuleID = r.ID
	}
	if n == 0 {
		return results
	}

	compiled := compileSet(s)
	space := newCellSpace(s)

	hit := make([]bool, n)   // some cell has this rule as first hit
	flips := make([]bool, n) // some first-hit cell changes action without it
	witnesses := make([]Packet, n)

	space.forEachCell(func(proto Protocol, port, addr uint32) {
		first := firstHit(compiled, -1, proto, port, addr)
		if first < 0 {
			return
		}
		hit[first] = true
		if flips[first] {
			return
		}
		without := actionAt(compiled, first, proto, port, addr)
		if without != compiled[first].action {
			flips[first] = true
			witnesses[first] = Packet{Proto: proto, Port: uint16(port), Addr: addr}
		}
	})

	for i := range results {
		switch {
		case !hit[i]:
			results[i].Class = Shadowed
		case !flips[i]:
			results[i].Class = Redundant
		default:
			results[i].Class = Effective
			w := witnesses[i]
			results[i].Witness = &w
		}
	}
	return results
}
