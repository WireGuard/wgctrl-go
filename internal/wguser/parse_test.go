package wguser

import (
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/mdlayher/wireguardctrl/wgtypes"
)

// Example string source (with some slight modifications to use all fields):
// https://www.wireguard.com/xplatform/#cross-platform-userspace-implementation.
const okGet = `private_key=e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a
listen_port=12912
fwmark=1
public_key=b85996fecc9c7f1fc6d2572a76eda11d59bcd20be8e543b15ce4bd85a8e75a33
preshared_key=188515093e952f5f22e865cef3012e72f8b5f0b598ac0309d5dacce3b70fcf52
allowed_ip=192.168.4.4/32
endpoint=[abcd:23::33%2]:51820
last_handshake_time_sec=1
last_handshake_time_nsec=2
public_key=58402e695ba1772b1cc9309755f043251ea77fdcf10fbe63989ceb7e19321376
tx_bytes=38333
rx_bytes=2224
allowed_ip=192.168.4.6/32
persistent_keepalive_interval=111
endpoint=182.122.22.19:3233
public_key=662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58
endpoint=5.152.198.39:51820
allowed_ip=192.168.4.10/32
allowed_ip=192.168.4.11/32
tx_bytes=1212111
rx_bytes=1929999999
errno=0

`

func TestClientDevices(t *testing.T) {
	// Used to trigger "parse peers" mode easily.
	const okKey = "public_key=0000000000000000000000000000000000000000000000000000000000000000\n"

	tests := []struct {
		name string
		res  []byte
		ok   bool
		d    *wgtypes.Device
	}{
		{
			name: "invalid key=value",
			res:  []byte("foo=bar=baz"),
		},
		{
			name: "invalid public_key",
			res:  []byte("public_key=xxx"),
		},
		{
			name: "short public_key",
			res:  []byte("public_key=abcd"),
		},
		{
			name: "invalid fwmark",
			res:  []byte("fwmark=foo"),
		},
		{
			name: "invalid endpoint",
			res:  []byte(okKey + "endpoint=foo"),
		},
		{
			name: "invalid allowed_ip",
			res:  []byte(okKey + "allowed_ip=foo"),
		},
		{
			name: "error",
			res:  []byte("errno=2\n\n"),
		},
		{
			name: "ok",
			res:  []byte(okGet),
			ok:   true,
			d: &wgtypes.Device{
				Name:       "testwg0",
				Type:       wgtypes.Userspace,
				PrivateKey: wgtypes.Key{0xe8, 0x4b, 0x5a, 0x6d, 0x27, 0x17, 0xc1, 0x0, 0x3a, 0x13, 0xb4, 0x31, 0x57, 0x3, 0x53, 0xdb, 0xac, 0xa9, 0x14, 0x6c, 0xf1, 0x50, 0xc5, 0xf8, 0x57, 0x56, 0x80, 0xfe, 0xba, 0x52, 0x2, 0x7a}, PublicKey: wgtypes.Key{0xc1, 0x53, 0x2e, 0x1b, 0x3d, 0x35, 0x8, 0xfc, 0x7e, 0xbc, 0x35, 0x4f, 0xa6, 0x79, 0x62, 0xf, 0x33, 0xf2, 0x87, 0x14, 0x95, 0x42, 0xe6, 0x84, 0xc6, 0x7b, 0x7b, 0xd, 0x81, 0x36, 0x2b, 0x29},
				ListenPort:   12912,
				FirewallMark: 1,
				Peers: []wgtypes.Peer{
					{
						PublicKey:    wgtypes.Key{0xb8, 0x59, 0x96, 0xfe, 0xcc, 0x9c, 0x7f, 0x1f, 0xc6, 0xd2, 0x57, 0x2a, 0x76, 0xed, 0xa1, 0x1d, 0x59, 0xbc, 0xd2, 0xb, 0xe8, 0xe5, 0x43, 0xb1, 0x5c, 0xe4, 0xbd, 0x85, 0xa8, 0xe7, 0x5a, 0x33},
						PresharedKey: wgtypes.Key{0x18, 0x85, 0x15, 0x9, 0x3e, 0x95, 0x2f, 0x5f, 0x22, 0xe8, 0x65, 0xce, 0xf3, 0x1, 0x2e, 0x72, 0xf8, 0xb5, 0xf0, 0xb5, 0x98, 0xac, 0x3, 0x9, 0xd5, 0xda, 0xcc, 0xe3, 0xb7, 0xf, 0xcf, 0x52},
						Endpoint: &net.UDPAddr{
							IP:   net.ParseIP("abcd:23::33"),
							Port: 51820,
							Zone: "2",
						},
						LastHandshakeTime: time.Unix(1, 2),
						AllowedIPs: []net.IPNet{
							{
								IP:   net.IP{0xc0, 0xa8, 0x4, 0x4},
								Mask: net.IPMask{0xff, 0xff, 0xff, 0xff},
							},
						},
					},
					{
						PublicKey:    wgtypes.Key{0x58, 0x40, 0x2e, 0x69, 0x5b, 0xa1, 0x77, 0x2b, 0x1c, 0xc9, 0x30, 0x97, 0x55, 0xf0, 0x43, 0x25, 0x1e, 0xa7, 0x7f, 0xdc, 0xf1, 0xf, 0xbe, 0x63, 0x98, 0x9c, 0xeb, 0x7e, 0x19, 0x32, 0x13, 0x76},
						PresharedKey: wgtypes.Key{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
						Endpoint: &net.UDPAddr{
							IP:   net.IPv4(182, 122, 22, 19),
							Port: 3233,
						},
						PersistentKeepaliveInterval: 111000000000,
						ReceiveBytes:                2224,
						TransmitBytes:               38333,
						AllowedIPs: []net.IPNet{
							{
								IP:   net.IP{0xc0, 0xa8, 0x4, 0x6},
								Mask: net.IPMask{0xff, 0xff, 0xff, 0xff},
							},
						},
					},
					{
						PublicKey: wgtypes.Key{0x66, 0x2e, 0x14, 0xfd, 0x59, 0x45, 0x56, 0xf5, 0x22, 0x60, 0x47, 0x3, 0x34, 0x3, 0x51, 0x25, 0x89, 0x3, 0xb6, 0x4f, 0x35, 0x55, 0x37, 0x63, 0xf1, 0x94, 0x26, 0xab, 0x2a, 0x51, 0x5c, 0x58},
						Endpoint: &net.UDPAddr{
							IP:   net.IPv4(5, 152, 198, 39),
							Port: 51820,
						},
						ReceiveBytes:  1929999999,
						TransmitBytes: 1212111,
						AllowedIPs: []net.IPNet{
							{
								IP:   net.IP{0xc0, 0xa8, 0x4, 0xa},
								Mask: net.IPMask{0xff, 0xff, 0xff, 0xff},
							},
							{
								IP:   net.IP{0xc0, 0xa8, 0x4, 0xb},
								Mask: net.IPMask{0xff, 0xff, 0xff, 0xff},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, done := testClient(t, tt.res)
			defer done()

			devs, err := c.Devices()

			if tt.ok && err != nil {
				t.Fatalf("failed to get devices: %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatal("expected an error, but none occurred")
			}
			if err != nil {
				return
			}

			if diff := cmp.Diff([]*wgtypes.Device{tt.d}, devs); diff != "" {
				t.Fatalf("unexpected Devices (-want +got):\n%s", diff)
			}
		})
	}
}
