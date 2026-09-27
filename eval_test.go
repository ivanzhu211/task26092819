package sgrules

import (
	"net/netip"
	"testing"
)

func mustSet(t *testing.T, rules []Rule) *RuleSet {
	t.Helper()
	s, err := NewRuleSet(rules)
	if err != nil {
		t.Fatalf("NewRuleSet: %v", err)
	}
	return s
}

func pkt(proto Protocol, port uint16, addr string) Packet {
	return Packet{Protocol: proto, Port: port, Addr: netip.MustParseAddr(addr)}
}

func pr(lo, hi uint16) *PortRange { return &PortRange{Lo: lo, Hi: hi} }

func TestEvaluateOrderAndDefault(t *testing.T) {
	s := mustSet(t, []Rule{
		{ID: 3, Priority: 10, Protocol: ProtocolTCP, Ports: pr(80, 80), CIDR: "10.0.0.0/24", Action: ActionAllow},
		{ID: 1, Priority: 10, Protocol: ProtocolTCP, Ports: pr(80, 80), CIDR: "10.0.0.0/24", Action: ActionDeny},
		{ID: 2, Priority: 10, Protocol: ProtocolTCP, Ports: pr(80, 80), CIDR: "10.0.0.0/24", Action: ActionDeny},
		{ID: 4, Priority: 5, Protocol: ProtocolAll, CIDR: "0.0.0.0/0", Action: ActionAllow},
	})
	// Priority 5 allow-all wins over everything.
	act, id, err := Evaluate(s, pkt(ProtocolTCP, 80, "10.0.0.7"))
	if err != nil || act != ActionAllow || id != 4 {
		t.Fatalf("got %v,%d,%v", act, id, err)
	}
	// Remove rule 4: same priority, deny before allow, ID 1 before 2.
	s2 := mustSet(t, []Rule{
		{ID: 3, Priority: 10, Protocol: ProtocolTCP, Ports: pr(80, 80), CIDR: "10.0.0.0/24", Action: ActionAllow},
		{ID: 1, Priority: 10, Protocol: ProtocolTCP, Ports: pr(80, 80), CIDR: "10.0.0.0/24", Action: ActionDeny},
		{ID: 2, Priority: 10, Protocol: ProtocolTCP, Ports: pr(80, 80), CIDR: "10.0.0.0/24", Action: ActionDeny},
	})
	act, id, err = Evaluate(s2, pkt(ProtocolTCP, 80, "10.0.0.7"))
	if err != nil || act != ActionDeny || id != 1 {
		t.Fatalf("got %v,%d,%v", act, id, err)
	}
	// No match -> default deny, ID 0.
	act, id, err = Evaluate(s2, pkt(ProtocolTCP, 81, "10.0.0.7"))
	if err != nil || act != ActionDeny || id != 0 {
		t.Fatalf("got %v,%d,%v", act, id, err)
	}
	// all-rule matches udp and icmp too.
	act, id, _ = Evaluate(s, pkt(ProtocolUDP, 53, "1.2.3.4"))
	if act != ActionAllow || id != 4 {
		t.Fatalf("got %v,%d", act, id)
	}
	act, id, _ = Evaluate(s, pkt(ProtocolICMP, 0, "255.255.255.255"))
	if act != ActionAllow || id != 4 {
		t.Fatalf("got %v,%d", act, id)
	}
}

func TestEvaluateBoundaries(t *testing.T) {
	s := mustSet(t, []Rule{
		{ID: 1, Priority: 1, Protocol: ProtocolTCP, Ports: pr(65535, 65535), CIDR: "0.0.0.0/0", Action: ActionAllow},
		{ID: 2, Priority: 2, Protocol: ProtocolUDP, Ports: pr(1, 1), CIDR: "255.255.255.255/32", Action: ActionAllow},
	})
	act, _, err := Evaluate(s, pkt(ProtocolTCP, 65535, "0.0.0.0"))
	if err != nil || act != ActionAllow {
		t.Fatalf("got %v,%v", act, err)
	}
	act, id, _ := Evaluate(s, pkt(ProtocolUDP, 1, "255.255.255.255"))
	if act != ActionAllow || id != 2 {
		t.Fatalf("got %v,%d", act, id)
	}
	act, _, _ = Evaluate(s, pkt(ProtocolUDP, 1, "255.255.255.254"))
	if act != ActionDeny {
		t.Fatalf("got %v", act)
	}
	if _, _, err := Evaluate(s, pkt(ProtocolICMP, 5, "1.1.1.1")); err == nil {
		t.Fatal("expected error for icmp with port")
	}
	if _, _, err := Evaluate(s, pkt(ProtocolTCP, 0, "1.1.1.1")); err == nil {
		t.Fatal("expected error for tcp port 0")
	}
}

func TestNewRuleSetValidation(t *testing.T) {
	good := Rule{ID: 1, Priority: 1, Protocol: ProtocolTCP, Ports: pr(1, 65535), CIDR: "0.0.0.0/0", Action: ActionAllow}
	cases := []struct {
		name string
		mut  func(r *Rule)
	}{
		{"bad id", func(r *Rule) { r.ID = 0 }},
		{"bad priority low", func(r *Rule) { r.Priority = 0 }},
		{"bad priority high", func(r *Rule) { r.Priority = 1001 }},
		{"bad protocol", func(r *Rule) { r.Protocol = "gre" }},
		{"bad action", func(r *Rule) { r.Action = "log" }},
		{"tcp missing ports", func(r *Rule) { r.Ports = nil }},
		{"port lo zero", func(r *Rule) { r.Ports = pr(0, 80) }},
		{"port inverted", func(r *Rule) { r.Ports = pr(90, 80) }},
		{"icmp with ports", func(r *Rule) { r.Protocol = ProtocolICMP }},
		{"all with ports", func(r *Rule) { r.Protocol = ProtocolAll }},
		{"host bits set", func(r *Rule) { r.CIDR = "10.0.0.1/24" }},
		{"bad cidr", func(r *Rule) { r.CIDR = "10.0.0.0/33" }},
		{"ipv6 cidr", func(r *Rule) { r.CIDR = "::/0" }},
	}
	for _, c := range cases {
		r := good
		c.mut(&r)
		if _, err := NewRuleSet([]Rule{r}); err == nil {
			t.Errorf("%s: expected error", c.name)
		}
	}
	// duplicate IDs
	r2 := good
	r2.ID = 1
	if _, err := NewRuleSet([]Rule{good, r2}); err == nil {
		t.Error("expected duplicate ID error")
	}
	// too many rules
	many := make([]Rule, 201)
	for i := range many {
		many[i] = good
		many[i].ID = i + 1
	}
	if _, err := NewRuleSet(many); err == nil {
		t.Error("expected too-many-rules error")
	}
	if _, err := NewRuleSet(many[:200]); err != nil {
		t.Errorf("200 rules should be ok: %v", err)
	}
	// /32 and /0 with zero host bits are legal
	if _, err := NewRuleSet([]Rule{
		{ID: 1, Priority: 1, Protocol: ProtocolICMP, CIDR: "255.255.255.255/32", Action: ActionDeny},
		{ID: 2, Priority: 2, Protocol: ProtocolAll, CIDR: "0.0.0.0/0", Action: ActionAllow},
	}); err != nil {
		t.Errorf("boundary CIDRs should be ok: %v", err)
	}
}
