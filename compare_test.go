package wgconf_test

import (
	"strings"
	"testing"

	"github.com/gentlemanautomaton/wgconf"
)

func TestCompareLists(t *testing.T) {
	t1 := wgconf.Peer{Name: "T1", PublicKey: mustParseKey(public1)}
	t2 := wgconf.Peer{Name: "T2", PublicKey: mustParseKey(public2)}
	t3a := wgconf.Peer{Name: "T3-A", PublicKey: mustParseKey(public3)}
	t3b := wgconf.Peer{Name: "T3-B", PublicKey: mustParseKey(public3)}
	t4 := wgconf.Peer{Name: "T4", PublicKey: mustParseKey(public4)}
	t5 := wgconf.Peer{Name: "T5", PublicKey: mustParseKey(public5)}
	t6 := wgconf.Peer{Name: "T6", PublicKey: mustParseKey(public6)}
	t7a := wgconf.Peer{Name: "T7", Description: "granite", PublicKey: mustParseKey(public7)}
	t7b := wgconf.Peer{Name: "T7", Description: "feldspar", PublicKey: mustParseKey(public7)}

	a := wgconf.PeerList{t1, t3a, t4, t5, t7a}
	b := wgconf.PeerList{t1, t2, t3b, t7b, t6}

	added, updated, removed, unchanged := wgconf.CompareLists(a, b)

	if diff := multilineDiff(testNames(added), `T2,T6`); diff != "" {
		t.Fatalf("comparison list returned unexpected values for added (-want +got):\n%s", diff)
	}
	if diff := multilineDiff(testNames(updated), `T3-B,T7`); diff != "" {
		t.Fatalf("comparison list returned unexpected values for updated (-want +got):\n%s", diff)
	}
	if diff := multilineDiff(testNames(removed), `T4,T5`); diff != "" {
		t.Fatalf("comparison list returned unexpected values for removed (-want +got):\n%s", diff)
	}
	if diff := multilineDiff(testNames(unchanged), `T1`); diff != "" {
		t.Fatalf("comparison list returned unexpected values for unchanged (-want +got):\n%s", diff)
	}
}

func testNames(peers wgconf.PeerList) string {
	var names []string
	for _, peer := range peers {
		names = append(names, peer.Name)
	}
	return strings.Join(names, ",")
}
