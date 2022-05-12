package wgconf

import (
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ReconcilePeers updates the peer list configuration for the given WireGuard
// device.
//
// The difference between the old peer list and the new peer list is used to
// determine the set of peer list changes that should be issued. Peers present
// in the old list but not present in the new list will be removed. Peers
// that are not present in either list will not be modified.
func ReconcilePeers(client *wgctrl.Client, device string, oldPeers, newPeers PeerList) error {
	// Compare the peers to determine what changes are necessary
	added, updated, removed, _ := CompareLists(oldPeers, newPeers)

	// Build a list of peer changes
	var peers []wgtypes.PeerConfig

	// Additions
	for _, peer := range added {
		peers = append(peers, wgtypes.PeerConfig{
			PublicKey:         peer.PublicKey,
			AllowedIPs:        peer.AllowedIPs,
			ReplaceAllowedIPs: true,
		})
	}

	// Updates
	for _, peer := range updated {
		peers = append(peers, wgtypes.PeerConfig{
			PublicKey:         peer.PublicKey,
			AllowedIPs:        peer.AllowedIPs,
			UpdateOnly:        true,
			ReplaceAllowedIPs: true,
		})
	}

	// Removals
	for _, peer := range removed {
		peers = append(peers, wgtypes.PeerConfig{
			PublicKey: peer.PublicKey,
			Remove:    true,
		})
	}

	// Issue the configuration change
	return client.ConfigureDevice(device, wgtypes.Config{
		Peers: peers,
	})
}
