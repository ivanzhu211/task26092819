package sgrules

// Protocol is the L4 protocol of a rule or packet.
type Protocol string

const (
	ProtoTCP  Protocol = "tcp"
	ProtoUDP  Protocol = "udp"
	ProtoICMP Protocol = "icmp"
	ProtoAll  Protocol = "all"
)

// Action is the decision produced by a rule or an evaluation.
type Action string

const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
)

// PortRange is a closed port interval [Lo, Hi], valid only for tcp/udp rules.
type PortRange struct {
	Lo uint16
	Hi uint16
}

// Rule is a single security-group rule.
type Rule struct {
	ID       uint32
	Priority uint16 // 1..1000, lower wins
	Proto    Protocol
	Ports    *PortRange // required for tcp/udp, must be nil for icmp/all
	CIDR     string     // IPv4 prefix, host bits must be zero
	Action   Action
}

// Packet is a (protocol, port, IPv4 address) triple.
// Port is meaningful only for tcp/udp packets; icmp packets use Port == 0.
type Packet struct {
	Proto Protocol
	Port  uint16
	Addr  uint32 // IPv4 address in network byte order as a uint32
}

// Classification is the per-rule verdict produced by Analyze.
type Classification int

const (
	// Shadowed: no packet has this rule as its first hit.
	Shadowed Classification = iota
	// Redundant: not shadowed, but deleting it alone changes no packet's action.
	Redundant
	// Effective: everything else; a witness packet is attached.
	Effective
)

// RuleAnalysis is the per-rule result of Analyze.
type RuleAnalysis struct {
	RuleID uint32
	Class  Classification
	// Witness is set only when Class == Effective: the rule is the first
	// hit on Witness, and deleting the rule flips Witness's action.
	Witness *Packet
}

// EquivalenceResult is the result of Equivalent.
type EquivalenceResult struct {
	Equivalent bool
	// Witness is set only when Equivalent == false: a and b decide
	// different actions on it.
	Witness *Packet
}
