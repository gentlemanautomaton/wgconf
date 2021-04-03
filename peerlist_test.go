package wgconf_test

import (
	"sort"
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
AllowedIPs=10.0.0.1/22,192.168.0.254/32,::/0

# T4 (four)
[WireGuardPeer]
PublicKey=aPxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10=
AllowedIPs=192.168.0.253/32,10.0.0.11/22`
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

func TestPeerListSortTypical(t *testing.T) {
	peers := selectTestPeers(tests, "Typical")
	sort.Sort(peers)
	expected := "T3,T1,T4,T2"
	var values []string
	for _, peer := range peers {
		values = append(values, peer.Name)
	}
	actual := strings.Join(values, ",")
	if diff := multilineDiff(actual, expected); diff != "" {
		t.Fatalf("unexpected PeerList.NetDev() output (-want +got):\n%s", diff)
	}
}

func TestPeerListSortCompare(t *testing.T) {
	peers := selectTestPeers(tests, "Compare")
	sort.Sort(peers)
	expected := "C6,C7,C8,C4,C5,C2,C3,C1"
	var values []string
	for _, peer := range peers {
		values = append(values, peer.Name)
	}
	actual := strings.Join(values, ",")
	if diff := multilineDiff(actual, expected); diff != "" {
		t.Fatalf("unexpected PeerList.NetDev() output (-want +got):\n%s", diff)
	}
}
