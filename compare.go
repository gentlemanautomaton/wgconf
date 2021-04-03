package wgconf

import "bytes"

// Compare provides a comparison function for peers. It is used by PeerList to
// determine its sort order. It returns the following values:
//  -1: Peer a is less than peer b
//   0: Peer a and b are equivalent
//   1: Peer a is greater than peer b
//
// Peers are by their allowed IP addresses, in ascending order. The public key
// is used as a tie breaker for peers lacking addresses.
func Compare(a, b Peer) int {
	// Compare IP addresses in AllowedIP lists
	alen, blen := len(a.AllowedIPs), len(b.AllowedIPs)
	for i := 0; i < alen && i < blen; i++ {
		if cmp := bytes.Compare(a.AllowedIPs[i].IP, b.AllowedIPs[i].IP); cmp != 0 {
			return cmp
		}
	}
	switch {
	case alen > blen:
		return -1
	case alen < blen:
		return 1
	}

	// Compare public keys
	if cmp := bytes.Compare(a.PublicKey[:], b.PublicKey[:]); cmp != 0 {
		return cmp
	}

	return 0
}
