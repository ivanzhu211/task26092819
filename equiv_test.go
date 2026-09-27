package sgrules

import "testing"

func TestEquivalentBasic(t *testing.T) {
	allowAll := []Rule{
		{ID: 1, Priority: 1, Protocol: ProtocolAll, CIDR: "0.0.0.0/0", Action: ActionAllow},
	}
	denyAll := []Rule{
		{ID: 1, Priority: 1, Protocol: ProtocolAll, CIDR: "0.0.0.0/0", Action: ActionDeny},
	}
	// empty set (default deny) == explicit deny-all
	eq, w := Equivalent(mustSet(t, nil), mustSet(t, denyAll))
	if !eq || w != nil {
		t.Fatalf("empty vs deny-all: got %v,%+v", eq, w)
	}
	// empty vs allow-all differ
	eq, w = Equivalent(mustSet(t, nil), mustSet(t, allowAll))
	if eq || w == nil {
		t.Fatalf("empty vs allow-all: got %v,%+v", eq, w)
	}
	act, _, err := Evaluate(mustSet(t, allowAll), *w)
	if err != nil || act != ActionAllow {
		t.Fatalf("witness evaluate: %v,%v", act, err)
	}
	// identical sets
	eq, _ = Equivalent(mustSet(t, allowAll), mustSet(t, allowAll))
	if !eq {
		t.Fatal("identical sets not equivalent")
	}
	// extra shadowed rule keeps equivalence
	withShadowed := []Rule{
		{ID: 1, Priority: 1, Protocol: ProtocolAll, CIDR: "0.0.0.0/0", Action: ActionAllow},
		{ID: 2, Priority: 2, Protocol: ProtocolTCP, Ports: pr(22, 22), CIDR: "10.0.0.0/8", Action: ActionDeny},
	}
	eq, w = Equivalent(mustSet(t, allowAll), mustSet(t, withShadowed))
	if !eq || w != nil {
		t.Fatalf("shadowed extra rule: got %v,%+v", eq, w)
	}
	// extra effective rule breaks equivalence; witness must flip between sets
	withEffective := []Rule{
		{ID: 1, Priority: 1, Protocol: ProtocolAll, CIDR: "0.0.0.0/0", Action: ActionAllow},
		{ID: 2, Priority: 2, Protocol: ProtocolICMP, CIDR: "10.0.0.0/8", Action: ActionDeny},
		{ID: 3, Priority: 0 + 1, Protocol: ProtocolTCP, Ports: pr(22, 22), CIDR: "10.0.0.0/8", Action: ActionDeny},
	}
	a, b := mustSet(t, allowAll), mustSet(t, withEffective)
	eq, w = Equivalent(a, b)
	if eq || w == nil {
		t.Fatalf("effective extra rule: got %v,%+v", eq, w)
	}
	actA, _, errA := Evaluate(a, *w)
	actB, _, errB := Evaluate(b, *w)
	if errA != nil || errB != nil || actA == actB {
		t.Fatalf("witness does not differ: %v vs %v (errs %v %v)", actA, actB, errA, errB)
	}
	// equivalence is symmetric in result (witness may differ)
	eq2, w2 := Equivalent(b, a)
	if eq2 || w2 == nil {
		t.Fatalf("reversed: got %v,%+v", eq2, w2)
	}
}

// Same function, different rule order and priorities -> equivalent.
func TestEquivalentReordered(t *testing.T) {
	a := mustSet(t, []Rule{
		{ID: 1, Priority: 1, Protocol: ProtocolTCP, Ports: pr(80, 80), CIDR: "10.0.0.0/24", Action: ActionAllow},
		{ID: 2, Priority: 2, Protocol: ProtocolAll, CIDR: "0.0.0.0/0", Action: ActionDeny},
	})
	b := mustSet(t, []Rule{
		{ID: 9, Priority: 1, Protocol: ProtocolAll, CIDR: "0.0.0.0/0", Action: ActionDeny},
		{ID: 8, Priority: 1, Protocol: ProtocolTCP, Ports: pr(80, 80), CIDR: "10.0.0.0/24", Action: ActionAllow},
	})
	// In b, deny-all has same priority but the allow is also priority 1;
	// deny wins ties, so b denies tcp:80 on 10.0.0.0/24 -> not equivalent.
	eq, w := Equivalent(a, b)
	if eq || w == nil {
		t.Fatalf("got %v,%+v", eq, w)
	}
	// Fix b: allow at higher precedence.
	b2 := mustSet(t, []Rule{
		{ID: 9, Priority: 2, Protocol: ProtocolAll, CIDR: "0.0.0.0/0", Action: ActionDeny},
		{ID: 8, Priority: 1, Protocol: ProtocolTCP, Ports: pr(80, 80), CIDR: "10.0.0.0/24", Action: ActionAllow},
	})
	eq, w = Equivalent(a, b2)
	if !eq || w != nil {
		t.Fatalf("got %v,%+v", eq, w)
	}
}
