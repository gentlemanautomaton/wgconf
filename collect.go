package wgconf

import "golang.zx2c4.com/wireguard/wgctrl"

// CollectPeers returns the current set of WireGuard peers for a device.
func CollectPeers(client *wgctrl.Client, device string) (PeerList, error) {
	dev, err := client.Device(device)
	if err != nil {
		return nil, err
	}
	var list PeerList
	for _, peer := range dev.Peers {
		list = append(list, Peer{
			PublicKey:  peer.PublicKey,
			AllowedIPs: peer.AllowedIPs,
		})
	}
	return list, nil
}
