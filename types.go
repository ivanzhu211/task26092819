// Package sgrules evaluates and statically analyzes security-group rule sets.
package sgrules

import "net/netip"

// Protocol identifies a network protocol. ProtocolAll is only valid on rules.
type Protocol string

const (
	ProtocolTCP  Protocol = "tcp"
	ProtocolUDP  Protocol = "udp"
	ProtocolICMP Protocol = "icmp"
	ProtocolAll  Protocol = "all"
)

// Action is the decision a rule takes on a matched packet.
type Action string

const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
)

// PortRange is a closed port interval, valid only on tcp/udp rules.
type PortRange struct {
	Lo uint16
	Hi uint16
}

// Rule is a single security-group rule.
type Rule struct {
	ID       int
	Priority int // 1..1000, lower matches first
	Protocol Protocol
	Ports    *PortRange // required for tcp/udp, must be nil for icmp/all
	CIDR     string     // IPv4 prefix, host bits must be zero
	Action   Action
}

// Packet is a (protocol, port, IPv4 address) triple.
// Port must be 0 for icmp and 1..65535 for tcp/udp.
type Packet struct {
	Protocol Protocol
	Port     uint16
	Addr     netip.Addr
}

// RuleClass is the static-analysis classification of a rule.
type RuleClass int

const (
	// Shadowed: no packet first-hits this rule.
	Shadowed RuleClass = iota
	// Redundant: not shadowed, but deleting it alone changes no packet's action.
	Redundant
	// Effective: neither shadowed nor redundant.
	Effective
)

// RuleAnalysis is the analysis verdict for one rule.
type RuleAnalysis struct {
	RuleID  int
	Class   RuleClass
	Witness *Packet // non-nil iff Class == Effective
}
