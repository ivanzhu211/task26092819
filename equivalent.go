package sgrules

// Equivalent reports whether a and b decide the same action for every
// possible packet. If not, it returns a witness packet on which they
// differ. The comparison is exact over the whole packet space.
func Equivalent(a, b *RuleSet) EquivalenceResult {
	ca, cb := compileSet(a), compileSet(b)
	space := newCellSpace(a, b)

	result := EquivalenceResult{Equivalent: true}
	space.forEachCell(func(proto Protocol, port, addr uint32) {
		if !result.Equivalent {
			return
		}
		if actionAt(ca, -1, proto, port, addr) != actionAt(cb, -1, proto, port, addr) {
			result.Equivalent = false
			result.Witness = &Packet{Proto: proto, Port: uint16(port), Addr: addr}
		}
	})
	return result
}
