package sgrules

import "fmt"

// Evaluate returns the action for a packet and the ID of the deciding rule
// (0 when the default deny applies).
func Evaluate(s *RuleSet, p Packet) (Action, int, error) {
	var addr uint32
	switch p.Protocol {
	case ProtocolTCP, ProtocolUDP:
		if p.Port < 1 {
			return "", 0, fmt.Errorf("%w: %s packet needs port 1-65535, got %d", errInvalidPacket, p.Protocol, p.Port)
		}
	case ProtocolICMP:
		if p.Port != 0 {
			return "", 0, fmt.Errorf("%w: icmp packet must have port 0, got %d", errInvalidPacket, p.Port)
		}
	default:
		return "", 0, fmt.Errorf("%w: protocol %q", errInvalidPacket, p.Protocol)
	}
	if !p.Addr.Is4() {
		return "", 0, fmt.Errorf("%w: address %v is not IPv4", errInvalidPacket, p.Addr)
	}
	addr = addr4ToUint32(p.Addr)
	for i := range s.rules {
		r := &s.rules[i]
		if addr < r.addrLo || addr > r.addrHi {
			continue
		}
		switch r.proto {
		case p.Protocol, ProtocolAll:
		default:
			continue
		}
		if r.proto == ProtocolTCP || r.proto == ProtocolUDP {
			if uint32(p.Port) < r.portLo || uint32(p.Port) > r.portHi {
				continue
			}
		}
		return r.action, r.id, nil
	}
	return ActionDeny, 0, nil
}
