package wgconf

import (
	"bytes"
	"sort"
	"strings"
)

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

	// Compare names
	if cmp := strings.Compare(a.Name, b.Name); cmp != 0 {
		return cmp
	}

	// Compare descriptions
	if cmp := strings.Compare(a.Description, b.Description); cmp != 0 {
		return cmp
	}

	return 0
}

// CompareLists compares a with b and determines the differences.
//
// Peers are uniquely identified by their public key.
func CompareLists(a, b PeerList) (added, updated, removed, unchanged PeerList) {
	// Prepare a map so we can look up existing peers by their public key
	lookup := make(map[Key]int)
	for i, peer := range a {
		lookup[peer.PublicKey] = i
	}

	// Process each new peer
	processed := make(map[Key]bool)
	for _, peer := range b {
		// When duplicate entries are present, ignore all but the first entry
		if processed[peer.PublicKey] {
			continue
		}
		if i, found := lookup[peer.PublicKey]; found {
			if Compare(a[i], peer) == 0 {
				unchanged = append(unchanged, peer)
			} else {
				updated = append(updated, peer)
			}
		} else {
			added = append(added, peer)
		}
		processed[peer.PublicKey] = true
	}

	// Find missing peers
	for _, peer := range a {
		if !processed[peer.PublicKey] {
			removed = append(removed, peer)
		}
	}

	// Sort return values
	sort.Sort(added)
	sort.Sort(updated)
	sort.Sort(removed)
	sort.Sort(unchanged)

	return
}
