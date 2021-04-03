package wgconf_test

import (
	"strings"
	"testing"

	"github.com/gentlemanautomaton/wgconf"
)

func TestPeerListNetDev(t *testing.T) {
	peers := selectTestPeers(tests, "Typical")
	expected := `# T1 (test.typical.one)
[WireGuardPeer]
PublicKey=aPxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10=
AllowedIPs=192.168.0.1/32

# T2 (two)
[WireGuardPeer]
PublicKey=aPxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10=
AllowedIPs=192.168.1.1/30

# T3 (thrice)
[WireGuardPeer]
PublicKey=aPxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10=
AllowedIPs=10.0.0.1/22,192.168.0.254/32,::/0`
	if diff := multilineDiff(peers.NetDev(), expected); diff != "" {
		t.Fatalf("unexpected PeerList.NetDev() output (-want +got):\n%s", diff)
	}
}

func selectTestPeers(list []PeerTest, prefix string) (peers wgconf.PeerList) {
	for _, tt := range tests {
		if strings.HasPrefix(tt.Name, prefix) {
			peers = append(peers, tt.Peer)
		}
	}
	return peers
}
