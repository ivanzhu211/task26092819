package sgrules

import "testing"

// analyzeByID runs Analyze and indexes the verdicts by rule ID.
func analyzeByID(t *testing.T, s *RuleSet) map[int]RuleAnalysis {
	t.Helper()
	out := make(map[int]RuleAnalysis)
	for _, ra := range Analyze(s) {
		out[ra.RuleID] = ra
		if ra.Class == Effective && ra.Witness == nil {
			t.Fatalf("rule %d effective without witness", ra.RuleID)
		}
		if ra.Class != Effective && ra.Witness != nil {
			t.Fatalf("rule %d non-effective with witness", ra.RuleID)
		}
	}
	return out
}

// TestJointShadowing: rule 3 (tcp 10.0.0.0/24:80) is covered only jointly:
// rule 1 covers the lower half by address (tcp), rule 2 (all protocols)
// covers the upper half. Neither alone shadows rule 3.
func TestJointShadowing(t *testing.T) {
	s := mustSet(t, []Rule{
		{ID: 1, Priority: 1, Protocol: ProtocolTCP, Ports: pr(80, 80), CIDR: "10.0.0.0/25", Action: ActionAllow},
		{ID: 2, Priority: 2, Protocol: ProtocolAll, CIDR: "10.0.0.128/25", Action: ActionDeny},
		{ID: 3, Priority: 3, Protocol: ProtocolTCP, Ports: pr(80, 80), CIDR: "10.0.0.0/24", Action: ActionAllow},
	})
	got := analyzeByID(t, s)
	if got[3].Class != Shadowed {
		t.Fatalf("rule 3: got class %v, want Shadowed", got[3].Class)
	}
	// Sanity: without rule 2, rule 3 is not shadowed.
	s2 := mustSet(t, []Rule{
		{ID: 1, Priority: 1, Protocol: ProtocolTCP, Ports: pr(80, 80), CIDR: "10.0.0.0/25", Action: ActionAllow},
		{ID: 3, Priority: 3, Protocol: ProtocolTCP, Ports: pr(80, 80), CIDR: "10.0.0.0/24", Action: ActionAllow},
	})
	if analyzeByID(t, s2)[3].Class == Shadowed {
		t.Fatal("rule 3 shadowed by rule 1 alone")
	}
	// Sanity: without rule 1, rule 3 is not shadowed.
	s3 := mustSet(t, []Rule{
		{ID: 2, Priority: 2, Protocol: ProtocolAll, CIDR: "10.0.0.128/25", Action: ActionDeny},
		{ID: 3, Priority: 3, Protocol: ProtocolTCP, Ports: pr(80, 80), CIDR: "10.0.0.0/24", Action: ActionAllow},
	})
	if analyzeByID(t, s3)[3].Class == Shadowed {
		t.Fatal("rule 3 shadowed by rule 2 alone")
	}
}

// TestRedundant: rule 2 (deny tcp 10.0.0.0/24:80) is partially covered above
// by rule 1 (allow, lower half). On the rest, default deny agrees with it.
func TestRedundant(t *testing.T) {
	s := mustSet(t, []Rule{
		{ID: 1, Priority: 1, Protocol: ProtocolTCP, Ports: pr(80, 80), CIDR: "10.0.0.0/25", Action: ActionAllow},
		{ID: 2, Priority: 2, Protocol: ProtocolTCP, Ports: pr(80, 80), CIDR: "10.0.0.0/24", Action: ActionDeny},
	})
	got := analyzeByID(t, s)
	if got[2].Class != Redundant {
		t.Fatalf("rule 2: got class %v, want Redundant", got[2].Class)
	}
	if got[1].Class != Effective {
		t.Fatalf("rule 1: got class %v, want Effective", got[1].Class)
	}
	// A lower allow rule on part of the remainder makes rule 2 effective.
	s2 := mustSet(t, []Rule{
		{ID: 1, Priority: 1, Protocol: ProtocolTCP, Ports: pr(80, 80), CIDR: "10.0.0.0/25", Action: ActionAllow},
		{ID: 2, Priority: 2, Protocol: ProtocolTCP, Ports: pr(80, 80), CIDR: "10.0.0.0/24", Action: ActionDeny},
		{ID: 3, Priority: 3, Protocol: ProtocolTCP, Ports: pr(80, 80), CIDR: "10.0.0.200/32", Action: ActionAllow},
	})
	got2 := analyzeByID(t, s2)
	if got2[2].Class != Effective {
		t.Fatalf("rule 2: got class %v, want Effective", got2[2].Class)
	}
	w := got2[2].Witness
	if w.Protocol != ProtocolTCP || w.Port != 80 {
		t.Fatalf("witness %+v not on tcp:80", w)
	}
}

// TestWitnessesFlip: for every effective rule, its witness packet must be
// decidable by Evaluate and must flip action when the rule is deleted.
func TestWitnessesFlip(t *testing.T) {
	sets := [][]Rule{
		{
			{ID: 1, Priority: 1, Protocol: ProtocolTCP, Ports: pr(80, 80), CIDR: "10.0.0.0/25", Action: ActionAllow},
			{ID: 2, Priority: 2, Protocol: ProtocolTCP, Ports: pr(80, 80), CIDR: "10.0.0.0/24", Action: ActionDeny},
			{ID: 3, Priority: 3, Protocol: ProtocolTCP, Ports: pr(80, 80), CIDR: "10.0.0.200/32", Action: ActionAllow},
		},
		{
			{ID: 1, Priority: 5, Protocol: ProtocolAll, CIDR: "0.0.0.0/0", Action: ActionDeny},
			{ID: 2, Priority: 1, Protocol: ProtocolUDP, Ports: pr(53, 53), CIDR: "8.8.8.8/32", Action: ActionAllow},
			{ID: 3, Priority: 2, Protocol: ProtocolICMP, CIDR: "10.1.0.0/16", Action: ActionAllow},
			{ID: 4, Priority: 3, Protocol: ProtocolTCP, Ports: pr(1, 65535), CIDR: "192.168.0.0/16", Action: ActionAllow},
		},
	}
	for _, rules := range sets {
		s := mustSet(t, rules)
		for _, ra := range Analyze(s) {
			if ra.Class != Effective {
				continue
			}
			before, id, err := Evaluate(s, *ra.Witness)
			if err != nil {
				t.Fatalf("witness not evaluable: %v", err)
			}
			if id != ra.RuleID {
				t.Fatalf("rule %d witness decided by rule %d", ra.RuleID, id)
			}
			var kept []Rule
			for _, r := range rules {
				if r.ID != ra.RuleID {
					kept = append(kept, r)
				}
			}
			after, _, err := Evaluate(mustSet(t, kept), *ra.Witness)
			if err != nil {
				t.Fatalf("witness not evaluable after delete: %v", err)
			}
			if after == before {
				t.Fatalf("rule %d witness did not flip (%v)", ra.RuleID, before)
			}
		}
	}
}

// TestShadowedByDefaultDenyIsNotAStrategy: a deny rule fully covered by
// higher allows is shadowed even though deleting it changes nothing.
func TestShadowedFullyCovered(t *testing.T) {
	s := mustSet(t, []Rule{
		{ID: 1, Priority: 1, Protocol: ProtocolAll, CIDR: "0.0.0.0/0", Action: ActionAllow},
		{ID: 2, Priority: 2, Protocol: ProtocolTCP, Ports: pr(22, 22), CIDR: "10.0.0.0/8", Action: ActionDeny},
	})
	if got := analyzeByID(t, s)[2].Class; got != Shadowed {
		t.Fatalf("got %v, want Shadowed", got)
	}
}
