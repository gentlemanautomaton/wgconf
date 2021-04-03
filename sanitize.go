package wgconf

import (
	"regexp"

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
