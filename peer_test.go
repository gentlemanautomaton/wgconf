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

const public1 = "aPxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10="
const public2 = "bPxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10="
const public3 = "cPxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10="
const public4 = "dPxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10="
const public5 = "ePxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10="
const public6 = "fPxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10="
const public7 = "gPxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10="

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
			PublicKey:   mustParseKey(public1),
			AllowedIPs:  []net.IPNet{mustParseIPNet("192.168.0.1/32")},
		},
		NetDev: "# T1 (test.typical.one)\n[WireGuardPeer]\nPublicKey=aPxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10=\nAllowedIPs=192.168.0.1/32",
	},
	{
		Name: "Typical2",
		Peer: wgconf.Peer{
			Name:        "T2",
			Description: "two",
			PublicKey:   mustParseKey(public1),
			AllowedIPs:  []net.IPNet{mustParseIPNet("192.168.1.1/30")},
		},
		NetDev: "# T2 (two)\n[WireGuardPeer]\nPublicKey=aPxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10=\nAllowedIPs=192.168.1.1/30",
	},
	{
		Name: "Typical3",
		Peer: wgconf.Peer{
			Name:        "T3",
			Description: "thrice",
			PublicKey:   mustParseKey(public1),
			AllowedIPs:  []net.IPNet{mustParseIPNet("10.0.0.1/22"), mustParseIPNet("192.168.0.254/32"), mustParseIPNet("::/0")},
		},
		NetDev: "# T3 (thrice)\n[WireGuardPeer]\nPublicKey=aPxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10=\nAllowedIPs=10.0.0.1/22,192.168.0.254/32,::/0",
	},
	{
		Name: "Typical4",
		Peer: wgconf.Peer{
			Name:        "T4",
			Description: "four",
			PublicKey:   mustParseKey(public1),
			AllowedIPs:  []net.IPNet{mustParseIPNet("192.168.0.253/32"), mustParseIPNet("10.0.0.11/22")},
		},
		NetDev: "# T4 (four)\n[WireGuardPeer]\nPublicKey=aPxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10=\nAllowedIPs=192.168.0.253/32,10.0.0.11/22",
	},
	{
		Name: "Filtered1",
		Peer: wgconf.Peer{
			Name:        "F1!$%*!@#$()@!#$^",
			Description: "test -filtered#@^#@&^ \n\n-one",
			PublicKey:   mustParseKey(public1),
			AllowedIPs:  []net.IPNet{mustParseIPNet("10.0.0.2/32")},
		},
		NetDev: "# F1 (test-filtered-one)\n[WireGuardPeer]\nPublicKey=aPxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10=\nAllowedIPs=10.0.0.2/32",
	},
	{
		Name: "Filtered2",
		Peer: wgconf.Peer{
			Name:        "F2",
			Description: "test-/filtered/-two",
			PublicKey:   mustParseKey(public1),
			AllowedIPs:  []net.IPNet{{}, {IP: net.IPv4(0, 0, 0, 0)}, mustParseIPNet("10.0.0.20/32"), {IP: net.IP{0}}},
		},
		NetDev: "# F2 (test-filtered-two)\n[WireGuardPeer]\nPublicKey=aPxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10=\nAllowedIPs=10.0.0.20/32",
	},
	{
		Name: "MissingName",
		Peer: wgconf.Peer{
			Description: "M1",
			PublicKey:   mustParseKey(public1),
			AllowedIPs:  []net.IPNet{mustParseIPNet("10.0.0.22/32")},
		},
		NetDev: "# M1\n[WireGuardPeer]\nPublicKey=aPxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10=\nAllowedIPs=10.0.0.22/32",
	},
	{
		Name: "MissingDescription",
		Peer: wgconf.Peer{
			Name:       "M2",
			PublicKey:  mustParseKey(public1),
			AllowedIPs: []net.IPNet{mustParseIPNet("10.0.0.23/32")},
		},
		NetDev: "# M2\n[WireGuardPeer]\nPublicKey=aPxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10=\nAllowedIPs=10.0.0.23/32",
	},
	{
		Name: "MissingPublicKey",
		Peer: wgconf.Peer{
			Name:        "M3",
			Description: "test.missing.three",
			AllowedIPs:  []net.IPNet{mustParseIPNet("10.0.0.24/32")},
		},
		NetDev: "# M3 (test.missing.three)\n#[WireGuardPeer]\n#PublicKey=\n#AllowedIPs=10.0.0.24/32",
	},
	{
		Name: "MissingAllowedIPs",
		Peer: wgconf.Peer{
			Name:        "M4",
			Description: "test.missing.four",
			PublicKey:   mustParseKey(public1),
		},
		NetDev: "# M4 (test.missing.four)\n#[WireGuardPeer]\n#PublicKey=aPxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10=\n#AllowedIPs=",
	},
	{
		Name: "Compare1",
		Peer: wgconf.Peer{
			Name:      "C1",
			PublicKey: mustParseKey(public3),
		},
		NetDev: "# C1\n#[WireGuardPeer]\n#PublicKey=cPxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10=\n#AllowedIPs=",
	},
	{
		Name: "Compare2",
		Peer: wgconf.Peer{
			Name:      "C2",
			PublicKey: mustParseKey(public1),
		},
		NetDev: "# C2\n#[WireGuardPeer]\n#PublicKey=aPxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10=\n#AllowedIPs=",
	},
	{
		Name: "Compare3",
		Peer: wgconf.Peer{
			Name:      "C3",
			PublicKey: mustParseKey(public2),
		},
		NetDev: "# C3\n#[WireGuardPeer]\n#PublicKey=bPxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10=\n#AllowedIPs=",
	},
	{
		Name: "Compare4",
		Peer: wgconf.Peer{
			Name:       "C4",
			PublicKey:  mustParseKey(public2),
			AllowedIPs: []net.IPNet{mustParseIPNet("10.0.0.35/32")},
		},
		NetDev: "# C4\n[WireGuardPeer]\nPublicKey=bPxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10=\nAllowedIPs=10.0.0.35/32",
	},
	{
		Name: "Compare5",
		Peer: wgconf.Peer{
			Name:       "C5",
			PublicKey:  mustParseKey(public1),
			AllowedIPs: []net.IPNet{mustParseIPNet("10.0.0.36/32")},
		},
		NetDev: "# C5\n[WireGuardPeer]\nPublicKey=aPxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10=\nAllowedIPs=10.0.0.36/32",
	},
	{
		Name: "Compare6",
		Peer: wgconf.Peer{
			Name:       "C6",
			PublicKey:  mustParseKey(public1),
			AllowedIPs: []net.IPNet{mustParseIPNet("10.0.0.30/32"), mustParseIPNet("10.0.0.31/32")},
		},
		NetDev: "# C6\n[WireGuardPeer]\nPublicKey=aPxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10=\nAllowedIPs=10.0.0.30/32,10.0.0.31/32",
	},
	{
		Name: "Compare7",
		Peer: wgconf.Peer{
			Name:       "C7",
			PublicKey:  mustParseKey(public1),
			AllowedIPs: []net.IPNet{mustParseIPNet("10.0.0.30/32")},
		},
		NetDev: "# C7\n[WireGuardPeer]\nPublicKey=aPxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10=\nAllowedIPs=10.0.0.30/32",
	},
	{
		Name: "Compare8",
		Peer: wgconf.Peer{
			Name:       "C8",
			PublicKey:  mustParseKey(public1),
			AllowedIPs: []net.IPNet{mustParseIPNet("10.0.0.30/32")},
		},
		NetDev: "# C8\n[WireGuardPeer]\nPublicKey=aPxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10=\nAllowedIPs=10.0.0.30/32",
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
	ip, network, err := net.ParseCIDR(ipnet)
	if err != nil {
		panic(err)
	}
	return net.IPNet{
		IP:   ip,
		Mask: network.Mask,
	}
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
