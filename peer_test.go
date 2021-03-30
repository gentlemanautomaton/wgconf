package wgconf_test

import (
	"net"
	"strings"
	"testing"

	"github.com/gentlemanautomaton/wgconf"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestPeerNetDev(t *testing.T) {
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			if diff := multilineDiff(tt.Peer.NetDev(), tt.NetDev); diff != "" {
				t.Fatalf("unexpected Peer.NetDev() output (-want +got):\n%s", diff)
			}
		})
	}
}

type PeerTest struct {
	Name   string
	Peer   wgconf.Peer
	NetDev string
}

const public = "aPxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10="

var tests = []PeerTest{
	{
		Name:   "Empty",
		Peer:   wgconf.Peer{},
		NetDev: "",
	},
	{
		Name: "Typical1",
		Peer: wgconf.Peer{
			Name:        "T1",
			Description: "test.typical.one",
			PublicKey:   mustParseKey(public),
			AllowedIPs:  []net.IPNet{mustParseIPNet("192.168.0.1/32")},
		},
		NetDev: "# T1 (test.typical.one)\n[WireGuardPeer]\nPublicKey=aPxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10=\nAllowedIPs=192.168.0.1/32",
	},
	{
		Name: "Typical2",
		Peer: wgconf.Peer{
			Name:        "T2",
			Description: "two",
			PublicKey:   mustParseKey(public),
			AllowedIPs:  []net.IPNet{mustParseIPNet("192.168.1.1/30")},
		},
		NetDev: "# T2 (two)\n[WireGuardPeer]\nPublicKey=aPxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10=\nAllowedIPs=192.168.1.0/30",
	},
	{
		Name: "Typical3",
		Peer: wgconf.Peer{
			Name:        "T3",
			Description: "thrice",
			PublicKey:   mustParseKey(public),
			AllowedIPs:  []net.IPNet{mustParseIPNet("10.0.0.1/22"), mustParseIPNet("192.168.0.254/32"), mustParseIPNet("::/0")},
		},
		NetDev: "# T3 (thrice)\n[WireGuardPeer]\nPublicKey=aPxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10=\nAllowedIPs=10.0.0.0/22,192.168.0.254/32,::/0",
	},
	{
		Name: "Filtered1",
		Peer: wgconf.Peer{
			Name:        "F1!$%*!@#$()@!#$^",
			Description: "test -filtered#@^#@&^ \n\n-one",
			PublicKey:   mustParseKey(public),
			AllowedIPs:  []net.IPNet{mustParseIPNet("10.0.0.1/32")},
		},
		NetDev: "# F1 (test-filtered-one)\n[WireGuardPeer]\nPublicKey=aPxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10=\nAllowedIPs=10.0.0.1/32",
	},
	{
		Name: "Filtered2",
		Peer: wgconf.Peer{
			Name:        "F2",
			Description: "test-/filtered/-two",
			PublicKey:   mustParseKey(public),
			AllowedIPs:  []net.IPNet{{}, {IP: net.IPv4(0, 0, 0, 0)}, mustParseIPNet("10.0.0.1/32"), {IP: net.IP{0}}},
		},
		NetDev: "# F2 (test-filtered-two)\n[WireGuardPeer]\nPublicKey=aPxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10=\nAllowedIPs=10.0.0.1/32",
	},
	{
		Name: "MissingName",
		Peer: wgconf.Peer{
			Description: "test.missing.one",
			PublicKey:   mustParseKey(public),
			AllowedIPs:  []net.IPNet{mustParseIPNet("10.0.0.1/32")},
		},
		NetDev: "# test.missing.one\n[WireGuardPeer]\nPublicKey=aPxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10=\nAllowedIPs=10.0.0.1/32",
	},
	{
		Name: "MissingDescription",
		Peer: wgconf.Peer{
			Name:       "M2",
			PublicKey:  mustParseKey(public),
			AllowedIPs: []net.IPNet{mustParseIPNet("10.0.0.1/32")},
		},
		NetDev: "# M2\n[WireGuardPeer]\nPublicKey=aPxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10=\nAllowedIPs=10.0.0.1/32",
	},
	{
		Name: "MissingPublicKey",
		Peer: wgconf.Peer{
			Name:        "M3",
			Description: "test.missing.three",
			AllowedIPs:  []net.IPNet{mustParseIPNet("10.0.0.1/32")},
		},
		NetDev: "# M3 (test.missing.three)\n#[WireGuardPeer]\n#PublicKey=\n#AllowedIPs=10.0.0.1/32",
	},
	{
		Name: "MissingAllowedIPs",
		Peer: wgconf.Peer{
			Name:        "M4",
			Description: "test.missing.four",
			PublicKey:   mustParseKey(public),
		},
		NetDev: "# M4 (test.missing.four)\n#[WireGuardPeer]\n#PublicKey=aPxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10=\n#AllowedIPs=",
	},
}

func mustParseKey(key string) wgtypes.Key {
	k, err := wgtypes.ParseKey(key)
	if err != nil {
		panic(err)
	}
	return k
}

func mustParseIPNet(ipnet string) net.IPNet {
	_, v, err := net.ParseCIDR(ipnet)
	if err != nil {
		panic(err)
	}
	return *v
}

func multilineDiff(actual, wanted string) string {
	if actual == wanted {
		return ""
	}
	return prefixLines(wanted, "-") + "\n" + prefixLines(actual, "+")
}

func prefixLines(in, prefix string) string {
	lines := strings.Split(in, "\n")
	return prefix + strings.Join(lines, "\n"+prefix)
}
