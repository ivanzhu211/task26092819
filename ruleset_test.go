package sgrules

import "testing"

func pr(lo, hi uint16) *PortRange { return &PortRange{Lo: lo, Hi: hi} }

func TestNewRuleSetValidation(t *testing.T) {
	valid := Rule{ID: 1, Priority: 1, Proto: ProtoTCP, Ports: pr(80, 80), CIDR: "10.0.0.0/8", Action: ActionAllow}
	cases := []struct {
		name  string
		rules []Rule
		want  bool // want error
	}{
		{"ok", []Rule{valid}, false},
		{"empty", nil, false},
		{"zero id", []Rule{{ID: 0, Priority: 1, Proto: ProtoICMP, CIDR: "0.0.0.0/0", Action: ActionDeny}}, true},
		{"dup id", []Rule{valid, {ID: 1, Priority: 2, Proto: ProtoUDP, Ports: pr(1, 2), CIDR: "0.0.0.0/0", Action: ActionDeny}}, true},
		{"priority 0", []Rule{{ID: 1, Priority: 0, Proto: ProtoICMP, CIDR: "0.0.0.0/0", Action: ActionDeny}}, true},
		{"priority 1001", []Rule{{ID: 1, Priority: 1001, Proto: ProtoICMP, CIDR: "0.0.0.0/0", Action: ActionDeny}}, true},
		{"priority 1000 ok", []Rule{{ID: 1, Priority: 1000, Proto: ProtoICMP, CIDR: "0.0.0.0/0", Action: ActionDeny}}, false},
		{"tcp nil ports", []Rule{{ID: 1, Priority: 1, Proto: ProtoTCP, CIDR: "0.0.0.0/0", Action: ActionDeny}}, true},
		{"icmp with ports", []Rule{{ID: 1, Priority: 1, Proto: ProtoICMP, Ports: pr(1, 1), CIDR: "0.0.0.0/0", Action: ActionDeny}}, true},
		{"all with ports", []Rule{{ID: 1, Priority: 1, Proto: ProtoAll, Ports: pr(1, 1), CIDR: "0.0.0.0/0", Action: ActionDeny}}, true},
		{"port lo 0", []Rule{{ID: 1, Priority: 1, Proto: ProtoTCP, Ports: pr(0, 10), CIDR: "0.0.0.0/0", Action: ActionDeny}}, true},
		{"port inverted", []Rule{{ID: 1, Priority: 1, Proto: ProtoTCP, Ports: pr(10, 1), CIDR: "0.0.0.0/0", Action: ActionDeny}}, true},
		{"port 65535 ok", []Rule{{ID: 1, Priority: 1, Proto: ProtoUDP, Ports: pr(65535, 65535), CIDR: "0.0.0.0/0", Action: ActionDeny}}, false},
		{"bad cidr", []Rule{{ID: 1, Priority: 1, Proto: ProtoICMP, CIDR: "10.0.0.0/33", Action: ActionDeny}}, true},
		{"host bits", []Rule{{ID: 1, Priority: 1, Proto: ProtoICMP, CIDR: "10.0.0.1/8", Action: ActionDeny}}, true},
		{"ipv6", []Rule{{ID: 1, Priority: 1, Proto: ProtoICMP, CIDR: "::/0", Action: ActionDeny}}, true},
		{"slash32 ok", []Rule{{ID: 1, Priority: 1, Proto: ProtoICMP, CIDR: "1.2.3.4/32", Action: ActionDeny}}, false},
		{"slash0 ok", []Rule{{ID: 1, Priority: 1, Proto: ProtoICMP, CIDR: "0.0.0.0/0", Action: ActionDeny}}, false},
		{"bad action", []Rule{{ID: 1, Priority: 1, Proto: ProtoICMP, CIDR: "0.0.0.0/0", Action: "drop"}}, true},
		{"bad proto", []Rule{{ID: 1, Priority: 1, Proto: "sctp", CIDR: "0.0.0.0/0", Action: ActionDeny}}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := NewRuleSet(c.rules)
			if (err != nil) != c.want {
				t.Fatalf("err=%v wantErr=%v", err, c.want)
			}
		})
	}
	tooMany := make([]Rule, 201)
	for i := range tooMany {
		tooMany[i] = Rule{ID: uint32(i + 1), Priority: 1, Proto: ProtoICMP, CIDR: "0.0.0.0/0", Action: ActionDeny}
	}
	if _, err := NewRuleSet(tooMany); err == nil {
		t.Fatal("expected error for 201 rules")
	}
}

func TestEvaluateOrderAndDefault(t *testing.T) {
	set, err := NewRuleSet([]Rule{
		{ID: 10, Priority: 5, Proto: ProtoTCP, Ports: pr(80, 80), CIDR: "0.0.0.0/0", Action: ActionAllow},
		{ID: 11, Priority: 5, Proto: ProtoTCP, Ports: pr(80, 80), CIDR: "0.0.0.0/0", Action: ActionDeny},
		{ID: 12, Priority: 1, Proto: ProtoAll, CIDR: "10.0.0.0/8", Action: ActionAllow},
		{ID: 13, Priority: 9, Proto: ProtoICMP, CIDR: "0.0.0.0/0", Action: ActionAllow},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Same priority: deny (11) beats allow (10).
	if act, id := Evaluate(set, Packet{Proto: ProtoTCP, Port: 80, Addr: 0x0b000001}); act != ActionDeny || id != 11 {
		t.Fatalf("got %v,%d", act, id)
	}
	// Lower priority number wins; all matches tcp any port.
	if act, id := Evaluate(set, Packet{Proto: ProtoTCP, Port: 22, Addr: 0x0a000001}); act != ActionAllow || id != 12 {
		t.Fatalf("got %v,%d", act, id)
	}
	// icmp matches rule 13.
	if act, id := Evaluate(set, Packet{Proto: ProtoICMP, Addr: 0x0b000001}); act != ActionAllow || id != 13 {
		t.Fatalf("got %v,%d", act, id)
	}
	// No match -> default deny, ID 0.
	if act, id := Evaluate(set, Packet{Proto: ProtoUDP, Port: 53, Addr: 0x0b000001}); act != ActionDeny || id != 0 {
		t.Fatalf("got %v,%d", act, id)
	}
	// all matches icmp too.
	if act, id := Evaluate(set, Packet{Proto: ProtoICMP, Addr: 0x0affffff}); act != ActionAllow || id != 12 {
		t.Fatalf("got %v,%d", act, id)
	}
}

func TestEvaluateBoundaries(t *testing.T) {
	set, err := NewRuleSet([]Rule{
		{ID: 1, Priority: 1, Proto: ProtoTCP, Ports: pr(65535, 65535), CIDR: "0.0.0.0/0", Action: ActionAllow},
		{ID: 2, Priority: 2, Proto: ProtoUDP, Ports: pr(1, 1), CIDR: "255.255.255.255/32", Action: ActionAllow},
	})
	if err != nil {
		t.Fatal(err)
	}
	if act, id := Evaluate(set, Packet{Proto: ProtoTCP, Port: 65535, Addr: 0xffffffff}); act != ActionAllow || id != 1 {
		t.Fatalf("got %v,%d", act, id)
	}
	if act, id := Evaluate(set, Packet{Proto: ProtoUDP, Port: 1, Addr: 0xffffffff}); act != ActionAllow || id != 2 {
		t.Fatalf("got %v,%d", act, id)
	}
	if act, id := Evaluate(set, Packet{Proto: ProtoUDP, Port: 1, Addr: 0xfffffffe}); act != ActionDeny || id != 0 {
		t.Fatalf("got %v,%d", act, id)
	}
}
