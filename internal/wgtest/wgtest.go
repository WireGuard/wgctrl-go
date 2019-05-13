package wgtest

import (
	"encoding/hex"
	"fmt"
	"net"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// MustCIDR converts CIDR string s into a net.IPNet or panics.
func MustCIDR(s string) net.IPNet {
	_, cidr, err := net.ParseCIDR(s)
	if err != nil {
		panicf("wgtest: failed to parse CIDR: %v", err)
	}

	return *cidr
}

// MustHexKey decodes a hex string s as a key or panics.
func MustHexKey(s string) wgtypes.Key {
	b, err := hex.DecodeString(s)
	if err != nil {
		panicf("wgtest: failed to decode hex key: %v", err)
	}

	k, err := wgtypes.NewKey(b)
	if err != nil {
		panicf("wgtest: failed to create key: %v", err)
	}

	return k
}

// MustPresharedKey generates a preshared key or panics.
func MustPresharedKey() wgtypes.Key {
	k, err := wgtypes.GenerateKey()
	if err != nil {
		panicf("wgtest: failed to generate preshared key: %v", err)
	}

	return k
}

// MustPrivateKey generates a private key or panics.
func MustPrivateKey() wgtypes.Key {
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		panicf("wgtest: failed to generate private key: %v", err)
	}

	return k
}

// MustPublicKey generates a public key or panics.
func MustPublicKey() wgtypes.Key {
	return MustPrivateKey().PublicKey()
}

// MustUDPAddr parses s as a UDP address or panics.
func MustUDPAddr(s string) *net.UDPAddr {
	a, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		panicf("wgtest: failed to resolve UDP address: %v", err)
	}

	return a
}

func panicf(format string, a ...interface{}) {
	panic(fmt.Sprintf(format, a...))
}
