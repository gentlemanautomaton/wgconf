package wgconf

import "strings"

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
