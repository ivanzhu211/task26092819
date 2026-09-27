package sgrules

import "testing"

func mustSet(t *testing.T, rules ...Rule) *RuleSet {
	t.Helper()
	s, err := NewRuleSet(rules)
	if err != nil {
		t.Fatalf("NewRuleSet: %v", err)
	}
	return s
}

func classByID(res []RuleAnalysis, id uint32) RuleAnalysis {
	for _, r := range res {
		if r.RuleID == id {
			return r
		}
	}
	panic("rule not found")
}

// deleteRule rebuilds the set without the given rule ID.
func deleteRule(t *testing.T, s *RuleSet, id uint32) *RuleSet {
	t.Helper()
	var kept []Rule
	for _, r := range s.Rules() {
		if r.ID != id {
			kept = append(kept, r)
		}
	}
	return mustSet(t, kept...)
}

// checkWitnesses verifies, for every Effective rule, that its witness is a
// valid packet on which the rule is the first hit and deleting the rule
// flips the witness's action — checked through the public Evaluate API.
func checkWitnesses(t *testing.T, s *RuleSet) {
	t.Helper()
	for _, ra := range Analyze(s) {
		if ra.Class != Effective {
			if ra.Witness != nil {
				t.Fatalf("rule %d: non-effective rule has a witness", ra.RuleID)
			}
			continue
		}
		if ra.Witness == nil {
			t.Fatalf("rule %d: effective rule missing witness", ra.RuleID)
		}
		w := *ra.Witness
		if w.Proto == ProtoICMP && w.Port != 0 {
			t.Fatalf("rule %d: icmp witness has a port: %+v", ra.RuleID, w)
		}
		if w.Proto != ProtoICMP && (w.Port < 1) {
			t.Fatalf("rule %d: witness port out of range: %+v", ra.RuleID, w)
		}
		before, idBefore := Evaluate(s, w)
		if idBefore != ra.RuleID {
			t.Fatalf("rule %d: witness %+v first-hits rule %d", ra.RuleID, w, idBefore)
		}
		after, _ := Evaluate(deleteRule(t, s, ra.RuleID), w)
		if after == before {
			t.Fatalf("rule %d: witness %+v action %s does not flip after deletion", ra.RuleID, w, before)
		}
	}
}

// Joint shadowing: rule 3 (tcp:80 on 10.0.0.0/8) is covered only by the
// union of rule 1 (tcp:80 on the lower half 10.0.0.0/9) and rule 2
// (all-protocols on the upper half 10.128.0.0/9). Neither alone shadows it.
func TestAnalyzeJointShadowing(t *testing.T) {
	set := mustSet(t,
		Rule{ID: 1, Priority: 50, Proto: ProtoTCP, Ports: pr(80, 80), CIDR: "10.0.0.0/9", Action: ActionDeny},
		Rule{ID: 2, Priority: 60, Proto: ProtoAll, CIDR: "10.128.0.0/9", Action: ActionAllow},
		Rule{ID: 3, Priority: 100, Proto: ProtoTCP, Ports: pr(80, 80), CIDR: "10.0.0.0/8", Action: ActionAllow},
	)
	res := Analyze(set)
	if got := classByID(res, 3).Class; got != Shadowed {
		t.Fatalf("rule 3: got class %v, want Shadowed", got)
	}
	// Sanity: removing either covering rule un-shadows rule 3.
	for _, id := range []uint32{1, 2} {
		res := Analyze(deleteRule(t, set, id))
		if got := classByID(res, 3).Class; got == Shadowed {
			t.Fatalf("without rule %d: rule 3 still Shadowed", id)
		}
	}
	checkWitnesses(t, set)
}

// Redundancy: rule 2 is partly overridden above (rule 1, same action deny
// is irrelevant — use allow above to carve its space), and on its remaining
// match space the lower rule and the default deny agree with its action.
func TestAnalyzeRedundant(t *testing.T) {
	set := mustSet(t,
		// Carves tcp:80 out of rule 2's space with a different action,
		// so rule 2 is NOT shadowed on ports 80-80... wait: rule 1 wins
		// on tcp:80; rule 2 remains first hit on tcp:1-79,81-1000.
		Rule{ID: 1, Priority: 10, Proto: ProtoTCP, Ports: pr(80, 80), CIDR: "10.0.0.0/8", Action: ActionAllow},
		Rule{ID: 2, Priority: 20, Proto: ProtoTCP, Ports: pr(1, 1000), CIDR: "10.0.0.0/8", Action: ActionDeny},
		// Below rule 2: same action (deny) on its remaining space.
		Rule{ID: 3, Priority: 30, Proto: ProtoTCP, Ports: pr(1, 1000), CIDR: "10.0.0.0/8", Action: ActionDeny},
	)
	res := Analyze(set)
	if got := classByID(res, 2).Class; got != Redundant {
		t.Fatalf("rule 2: got class %v, want Redundant", got)
	}
	if got := classByID(res, 1).Class; got != Effective {
		t.Fatalf("rule 1: got class %v, want Effective", got)
	}
	// Rule 3 is shadowed by rule 2 (identical match space, lower priority).
	if got := classByID(res, 3).Class; got != Shadowed {
		t.Fatalf("rule 3: got class %v, want Shadowed", got)
	}
	checkWitnesses(t, set)
}

// Redundancy via default deny: no lower rule at all, but the remaining
// space of a deny rule falls through to the default deny.
func TestAnalyzeRedundantViaDefaultDeny(t *testing.T) {
	set := mustSet(t,
		Rule{ID: 1, Priority: 10, Proto: ProtoTCP, Ports: pr(80, 80), CIDR: "10.0.0.0/8", Action: ActionAllow},
		Rule{ID: 2, Priority: 20, Proto: ProtoTCP, Ports: pr(1, 1000), CIDR: "10.0.0.0/8", Action: ActionDeny},
	)
	res := Analyze(set)
	if got := classByID(res, 2).Class; got != Redundant {
		t.Fatalf("rule 2: got class %v, want Redundant", got)
	}
	checkWitnesses(t, set)
}

func TestAnalyzeEffective(t *testing.T) {
	set := mustSet(t,
		Rule{ID: 1, Priority: 10, Proto: ProtoTCP, Ports: pr(80, 80), CIDR: "10.0.0.0/8", Action: ActionAllow},
		Rule{ID: 2, Priority: 20, Proto: ProtoAll, CIDR: "0.0.0.0/0", Action: ActionDeny},
		Rule{ID: 3, Priority: 30, Proto: ProtoAll, CIDR: "0.0.0.0/0", Action: ActionAllow},
	)
	res := Analyze(set)
	for _, id := range []uint32{1, 2} {
		if got := classByID(res, id).Class; got != Effective {
			t.Fatalf("rule %d: got class %v, want Effective", id, got)
		}
	}
	// Rule 3 never wins: rule 2 above it covers the whole space.
	if got := classByID(res, 3).Class; got != Shadowed {
		t.Fatalf("rule 3: got class %v, want Shadowed", got)
	}
	checkWitnesses(t, set)
}

// icmp and all mixed: an all-rule must not shadow an icmp-specific space
// verdict incorrectly, and port-carrying rules never match icmp cells.
func TestAnalyzeICMPAndAll(t *testing.T) {
	set := mustSet(t,
		Rule{ID: 1, Priority: 10, Proto: ProtoAll, CIDR: "10.0.0.0/8", Action: ActionAllow},
		Rule{ID: 2, Priority: 20, Proto: ProtoICMP, CIDR: "10.0.0.0/8", Action: ActionDeny},
		Rule{ID: 3, Priority: 30, Proto: ProtoTCP, Ports: pr(1, 65535), CIDR: "0.0.0.0/0", Action: ActionAllow},
	)
	res := Analyze(set)
	if got := classByID(res, 2).Class; got != Shadowed {
		t.Fatalf("rule 2: got class %v, want Shadowed (all-rule above covers icmp)", got)
	}
	if got := classByID(res, 1).Class; got != Effective {
		t.Fatalf("rule 1: got class %v, want Effective", got)
	}
	if got := classByID(res, 3).Class; got != Effective {
		t.Fatalf("rule 3: got class %v, want Effective", got)
	}
	checkWitnesses(t, set)
}

func TestAnalyzeEmpty(t *testing.T) {
	set := mustSet(t)
	if res := Analyze(set); len(res) != 0 {
		t.Fatalf("got %d results for empty set", len(res))
	}
}
