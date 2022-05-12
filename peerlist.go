package wgconf

import (
	"strings"
)

// PeerList is a list of WireGuard peers.
type PeerList []Peer

// NetDev returns the systemd netdev configuration for the peers.
func (list PeerList) NetDev() string {
	var entries []string
	for _, peer := range list {
		if entry := peer.NetDev(); entry != "" {
			entries = append(entries, entry)
		}
	}
	return strings.Join(entries, "\n\n")
}

// Len returns the number of peers in the list.
func (list PeerList) Len() int {
	return len(list)
}

// Less reports whether the peer with index i must sort before the peer
// with index j. The order is based on the Compare function.
func (list PeerList) Less(i, j int) bool {
	return Compare(list[i], list[j]) < 0
}

// Swap swaps the peers with indexes i and j.
func (list PeerList) Swap(i, j int) {
	list[i], list[j] = list[j], list[i]
}

// Match returns the set of peers that match the given filter.
func (list PeerList) Match(filter PeerFilter) PeerList {
	filtered := make(PeerList, 0, len(list))
	for _, peer := range list {
		if filter(peer) {
			filtered = append(filtered, peer)
		}
	}
	return filtered
}
