package sgrules

import "testing"

func TestEquivalentIdenticalAndReordered(t *testing.T) {
	a := mustSet(t,
		Rule{ID: 1, Priority: 10, Proto: ProtoTCP, Ports: pr(80, 80), CIDR: "10.0.0.0/8", Action: ActionAllow},
		Rule{ID: 2, Priority: 20, Proto: ProtoAll, CIDR: "0.0.0.0/0", Action: ActionDeny},
	)
	b := mustSet(t,
		Rule{ID: 2, Priority: 20, Proto: ProtoAll, CIDR: "0.0.0.0/0", Action: ActionDeny},
		Rule{ID: 1, Priority: 10, Proto: ProtoTCP, Ports: pr(80, 80), CIDR: "10.0.0.0/8", Action: ActionAllow},
	)
	if !Equivalent(a, b).Equivalent {
		t.Fatal("identical sets should be equivalent")
	}
	if !Equivalent(a, a).Equivalent {
		t.Fatal("set should be equivalent to itself")
	}
}

// Different rule lists, same semantics: b's extra rule is redundant.
func TestEquivalentSemanticallyEqual(t *testing.T) {
	a := mustSet(t,
		Rule{ID: 1, Priority: 10, Proto: ProtoTCP, Ports: pr(1, 1000), CIDR: "10.0.0.0/8", Action: ActionAllow},
	)
	b := mustSet(t,
		Rule{ID: 1, Priority: 10, Proto: ProtoTCP, Ports: pr(1, 500), CIDR: "10.0.0.0/8", Action: ActionAllow},
		Rule{ID: 2, Priority: 20, Proto: ProtoTCP, Ports: pr(501, 1000), CIDR: "10.0.0.0/8", Action: ActionAllow},
	)
	if !Equivalent(a, b).Equivalent {
		t.Fatal("split range should be equivalent")
	}
}

func TestEquivalentWitness(t *testing.T) {
	a := mustSet(t,
		Rule{ID: 1, Priority: 10, Proto: ProtoTCP, Ports: pr(80, 80), CIDR: "10.0.0.0/8", Action: ActionAllow},
	)
	b := mustSet(t,
		Rule{ID: 1, Priority: 10, Proto: ProtoTCP, Ports: pr(80, 80), CIDR: "10.0.0.0/8", Action: ActionDeny},
	)
	res := Equivalent(a, b)
	if res.Equivalent {
		t.Fatal("allow vs deny should differ")
	}
	if res.Witness == nil {
		t.Fatal("missing witness")
	}
	actA, _ := Evaluate(a, *res.Witness)
	actB, _ := Evaluate(b, *res.Witness)
	if actA == actB {
		t.Fatalf("witness %+v decides %s on both", *res.Witness, actA)
	}
}

func TestEquivalentEmptyVsNonEmpty(t *testing.T) {
	empty := mustSet(t)
	denyAll := mustSet(t,
		Rule{ID: 1, Priority: 1, Proto: ProtoAll, CIDR: "0.0.0.0/0", Action: ActionDeny},
	)
	allowAll := mustSet(t,
		Rule{ID: 1, Priority: 1, Proto: ProtoAll, CIDR: "0.0.0.0/0", Action: ActionAllow},
	)
	if !Equivalent(empty, denyAll).Equivalent {
		t.Fatal("empty set defaults to deny; should equal explicit deny-all")
	}
	res := Equivalent(empty, allowAll)
	if res.Equivalent || res.Witness == nil {
		t.Fatal("empty vs allow-all should differ with a witness")
	}
}
