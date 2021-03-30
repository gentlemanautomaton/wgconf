package wgconf

import (
	"net"
	"regexp"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var alphaNumeric = regexp.MustCompile(`[^a-zA-Z0-9\.\-]`)

var zeroKey = wgtypes.Key{}

func sanitizeComment(comment string) string {
	return alphaNumeric.ReplaceAllString(comment, "")
}

func sanitizeKey(key wgtypes.Key) string {
	if key == zeroKey {
		return ""
	}
	return key.String()
}

func sanitizeIPs(ipnets []net.IPNet) string {
	var addrs []string
	for _, ipnet := range ipnets {
		if !validIP(ipnet.IP) || !validMask(ipnet.Mask) {
			continue
		}
		addrs = append(addrs, ipnet.String())
	}
	return strings.Join(addrs, ",")
}

func validIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.To4() != nil {
		return true
	}
	if len(ip) == net.IPv6len {
		return true
	}
	return false
}

func validMask(mask net.IPMask) bool {
	return mask != nil
}
