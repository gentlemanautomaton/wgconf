package wgconf

import (
	"fmt"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Key is a public or private key used by WireGuard.
type Key = wgtypes.Key

// Peer is a WireGuard peer.
type Peer struct {
	Name        string
	Description string
	PublicKey   Key
	AllowedIPs  AllowedIPs
}

// NetDev returns the systemd netdev configuration for the peer.
func (p Peer) NetDev() string {
	// Collect sanitized string representations of each field
	name := sanitizeComment(p.Name)
	description := sanitizeComment(p.Description)
	pubkey := sanitizeKey(p.PublicKey)
	addrs := p.AllowedIPs.String()

	// Reject keyless peers without a comment
	if name == "" && description == "" && pubkey == "" {
		return ""
	}

	// Aggregate the peer configuration with a string builder
	var sb strings.Builder

	// Include a leading comment with the peer name and/or description
	switch {
	case name != "" && description != "":
		sb.WriteString(fmt.Sprintf("# %s (%s)\n", name, description))
	case name != "":
		sb.WriteString(fmt.Sprintf("# %s\n", name))
	case description != "":
		sb.WriteString(fmt.Sprintf("# %s\n", description))
	}

	// Include the WireGuardPeer entry
	if pubkey == "" || addrs == "" {
		sb.WriteString("#[WireGuardPeer]\n")
		sb.WriteString(fmt.Sprintf("#PublicKey=%s\n", pubkey))
		sb.WriteString(fmt.Sprintf("#AllowedIPs=%s", addrs))
	} else {
		sb.WriteString("[WireGuardPeer]\n")
		sb.WriteString(fmt.Sprintf("PublicKey=%s\n", pubkey))
		sb.WriteString(fmt.Sprintf("AllowedIPs=%s", addrs))
	}

	return sb.String()
}
