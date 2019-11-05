package config

import (
	"bytes"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func newSource() *bytes.Buffer {
	const s = `
[Interface]
ListenPort = 51820
PrivateKey = XbHLxgz75/yVgxeQoTegSTQlrpWObIcnqlAWzawY3SI=
FwMark = 10

[Peer]
# foo
PublicKey = wALKCWOGCXMNISqMgJNa6DwNxe62fzKYRgtuIM1NGVc=
PresharedKey = W9tyo4+5i39K58Tm3TyJ9M7R9o2IU8RMttloSRzTjZI=
AllowedIPs = 10.200.200.2/32, 10.200.200.3/24
Endpoint = 192.168.0.100:7777

[Peer]
# bar
PublicKey = z+H+iGabx7HcDfL+vh6DD/ARlY0CgFe7rC+lu/9fC9w=
`
	return bytes.NewBufferString(s)
}

func TestLoadConfig(t *testing.T) {
	cfg, err := ParseConfig(newSource())
	assert.NoError(t, err)
	assert.Equal(t, 51820, *cfg.ListenPort)
	key, err := wgtypes.ParseKey("XbHLxgz75/yVgxeQoTegSTQlrpWObIcnqlAWzawY3SI=")
	assert.NoError(t, err)
	assert.Equal(t, key, *cfg.PrivateKey)
	assert.Equal(t, 10, *cfg.FirewallMark)
	assert.Equal(t, 2, len(cfg.Peers))

	peer0 := cfg.Peers[0]
	assert.Equal(t, net.ParseIP("192.168.0.100"), peer0.Endpoint.IP)
	assert.Equal(t, 7777, peer0.Endpoint.Port)
	assert.Equal(t, 2, len(peer0.AllowedIPs))
	allowedIPs := peer0.AllowedIPs
	assert.True(t, net.IPv4(10, 200, 200, 2).Equal(allowedIPs[0].IP))
	assert.Equal(t, net.IPv4Mask(255, 255, 255, 255), allowedIPs[0].Mask)
	assert.True(t, net.IPv4(10, 200, 200, 0).Equal(allowedIPs[1].IP))
	assert.Equal(t, net.IPv4Mask(255, 255, 255, 0), allowedIPs[1].Mask)
	assert.Equal(t, mustDecodeKey("wALKCWOGCXMNISqMgJNa6DwNxe62fzKYRgtuIM1NGVc="), peer0.PublicKey)
	assert.Equal(t, mustDecodeKey("W9tyo4+5i39K58Tm3TyJ9M7R9o2IU8RMttloSRzTjZI="), *peer0.PresharedKey)

	peer1 := cfg.Peers[1]
	assert.Equal(t, mustDecodeKey("z+H+iGabx7HcDfL+vh6DD/ARlY0CgFe7rC+lu/9fC9w="), peer1.PublicKey)
}

func mustDecodeKey(s string) wgtypes.Key {
	key, err := wgtypes.ParseKey(s)
	if err != nil {
		panic(err)
	}
	return key
}
