# wgconf [![Go Reference](https://pkg.go.dev/badge/github.com/gentlemanautomaton/wgconf.svg)](https://pkg.go.dev/github.com/gentlemanautomaton/wgconf)

Package `wgconf` provides a limited set of WireGuard configuration types that can be marshaled as systemd netdev configuration.

## Example

```go
package main

import (
	"fmt"
	"net"

	"github.com/gentlemanautomaton/wgconf"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func main() {
	peers := wgconf.PeerList{
		{
			Name:        "Laptop1",
			Description: "alice.laptop",
			PublicKey:   ParseKey("lO/VBDYf0zKo4N+RwnjNsBYMb8Wuw8WUZP00C7CviS0="),
			AllowedIPs:  []net.IPNet{ParseIPNet("10.0.0.1/32")},
		},
		{
			Name:        "Laptop2",
			Description: "bob.laptop",
			PublicKey:   ParseKey("uEVNLxM71801qc3xOYsgvoKjX3AaK6+CV3c8tzjR0iE="),
			AllowedIPs:  []net.IPNet{ParseIPNet("10.0.0.2/32"), ParseIPNet("192.168.0.254/32")},
		},
	}
	fmt.Print(peers.NetDev())
}

func ParseKey(key string) wgtypes.Key {
	k, err := wgtypes.ParseKey(key)
	if err != nil {
		panic(err)
	}
	return k
}

func ParseIPNet(cidr string) net.IPNet {
	_, v, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	return *v
}
```

Example Output:

```
# Laptop1 (alice.laptop)
[WireGuardPeer]
PublicKey=lO/VBDYf0zKo4N+RwnjNsBYMb8Wuw8WUZP00C7CviS0=
AllowedIPs=10.0.0.1/32

# Laptop2 (bob.laptop)
[WireGuardPeer]
PublicKey=uEVNLxM71801qc3xOYsgvoKjX3AaK6+CV3c8tzjR0iE=
AllowedIPs=10.0.0.2/32,192.168.0.254/32
```