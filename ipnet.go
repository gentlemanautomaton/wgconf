package wgconf

import "net"

// IPNet is an IP Network that can be used to filter peers.
type IPNet net.IPNet

// Contains returns true if all of the peer's allowed IP networks are
// contained within ipnet.
func (ipnet IPNet) Contains(p Peer) bool {
	if len(p.AllowedIPs) == 0 {
		return false
	}
	for _, allowed := range p.AllowedIPs {
		if !containedIPNet(net.IPNet(ipnet), allowed) {
			return false
		}
	}
	return true
}

func containedIPNet(parent, child net.IPNet) bool {
	parentOnes, _ := parent.Mask.Size()
	childOnes, _ := child.Mask.Size()
	if parentOnes > childOnes {
		// The parent mask is smaller than the child, and therefore
		// cannot contain it
		return false
	}
	return parent.Contains(child.IP)
}
