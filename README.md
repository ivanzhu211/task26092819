# task26092819

`sgrules` — a Go library for evaluating and statically analyzing one
direction of a security-group rule set. Used by the VPC control plane to
check rule changes and version rollbacks before they are applied.

## Model

- A rule: positive unique ID, priority 1–1000, protocol (`tcp`/`udp`/`icmp`/`all`),
  optional closed port range (tcp/udp only, 1–65535), an IPv4 CIDR
  (host bits must be zero; `0.0.0.0/0` and `/32` allowed), action `allow`/`deny`.
- A packet: protocol, port (0 for icmp), IPv4 address.
- Match order is total: lower priority value first, ties broken by
  `deny` before `allow`, then by ascending ID. First hit decides;
  no hit means default deny (rule ID 0).
- At most 200 rules per set.

## API

- `NewRuleSet([]Rule) (*RuleSet, error)` — validate and build.
- `Evaluate(*RuleSet, Packet) (Action, int, error)` — decide one packet.
- `Analyze(*RuleSet) []RuleAnalysis` — classify each rule (match order):
  - `Shadowed` — no packet first-hits it (joint cover by several
    higher rules counts);
  - `Redundant` — not shadowed, but deleting it alone changes nothing;
  - `Effective` — otherwise; carries a `Witness` packet that first-hits
    the rule and flips action when the rule is deleted.
- `Equivalent(a, b *RuleSet) (bool, *Packet)` — decide whether two sets
  agree on every packet; otherwise return a differing witness packet.

## How it works

Per protocol space (tcp/udp: port×address, icmp: address only), the
packet universe is partitioned into elementary cells using every rule's
CIDR and port-range boundaries. On each cell the matching rule set is
constant, so scanning rules in match order per cell yields exact
first-hit / second-hit information — no sampling, no truncation, no
per-port×per-address enumeration. 200-rule `Analyze` and 200×200
`Equivalent` each run in well under a millisecond to a few milliseconds.

## Tests

    go test ./...

Covers joint shadowing, redundancy, witness-flip verification through
`Evaluate`, boundary values (`0.0.0.0/0`, port 65535, icmp/all mixes),
a randomized differential comparison against a test-only point-by-point
exhaustive reference, and 200-rule performance bounds.
