package wgconf

import (
	"net"
	"strings"
)

// AllowedIPs is a slice of network addresses that are assigned to a WireGuard
// peers.
type AllowedIPs []net.IPNet

// String returns a comma-separated AllowedIPs string for the given
// IP networks. Invalid networks will be omitted.
func (ipnets AllowedIPs) String() string {
	var addrs []string
	for _, ipnet := range ipnets {
		if !validIP(ipnet.IP) || !validMask(ipnet.Mask) {
			continue
		}
		addrs = append(addrs, ipnet.String())
	}
	return strings.Join(addrs, ",")
}

func validIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.To4() != nil {
		return true
	}
	if len(ip) == net.IPv6len {
		return true
	}
	return false
}

func validMask(mask net.IPMask) bool {
	return mask != nil
}
