//+build linux

package wgnl

import (
	"net"
	"testing"
	"time"
	"unsafe"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/genetlink/genltest"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"github.com/mdlayher/netlink/nltest"
	"github.com/mdlayher/wireguardctrl/internal/wgnl/internal/wgh"
	"github.com/mdlayher/wireguardctrl/internal/wgtest"
	"github.com/mdlayher/wireguardctrl/wgtypes"
	"golang.org/x/sys/unix"
)

func TestLinuxClientConfigureDevice(t *testing.T) {
	nameAttr := netlink.Attribute{
		Type: wgh.DeviceAIfname,
		Data: nlenc.Bytes(okName),
	}

	tests := []struct {
		name  string
		cfg   wgtypes.Config
		attrs []netlink.Attribute
		ok    bool
	}{
		{
			name: "bad peer endpoint",
			cfg: wgtypes.Config{
				Peers: []wgtypes.PeerConfig{{
					Endpoint: &net.UDPAddr{
						IP: net.IP{0xff},
					},
				}},
			},
		},
		{
			name: "bad peer allowed IP",
			cfg: wgtypes.Config{
				Peers: []wgtypes.PeerConfig{{
					AllowedIPs: []net.IPNet{{
						IP: net.IP{0xff},
					}},
				}},
			},
		},
		{
			name: "ok, none",
			attrs: []netlink.Attribute{
				nameAttr,
			},
			ok: true,
		},
		{
			name: "ok, all",
			cfg: wgtypes.Config{
				PrivateKey:   keyPtr(wgtest.MustHexKey("e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a")),
				ListenPort:   intPtr(12912),
				FirewallMark: intPtr(0),
				ReplacePeers: true,
				Peers: []wgtypes.PeerConfig{
					{
						PublicKey:         wgtest.MustHexKey("b85996fecc9c7f1fc6d2572a76eda11d59bcd20be8e543b15ce4bd85a8e75a33"),
						PresharedKey:      keyPtr(wgtest.MustHexKey("188515093e952f5f22e865cef3012e72f8b5f0b598ac0309d5dacce3b70fcf52")),
						Endpoint:          wgtest.MustUDPAddr("[abcd:23::33%2]:51820"),
						ReplaceAllowedIPs: true,
						AllowedIPs: []net.IPNet{
							wgtest.MustCIDR("192.168.4.4/32"),
						},
					},
					{
						PublicKey:                   wgtest.MustHexKey("58402e695ba1772b1cc9309755f043251ea77fdcf10fbe63989ceb7e19321376"),
						Endpoint:                    wgtest.MustUDPAddr("182.122.22.19:3233"),
						PersistentKeepaliveInterval: durPtr(111 * time.Second),
						ReplaceAllowedIPs:           true,
						AllowedIPs: []net.IPNet{
							wgtest.MustCIDR("192.168.4.6/32"),
						},
					},
					{
						PublicKey:         wgtest.MustHexKey("662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58"),
						Endpoint:          wgtest.MustUDPAddr("5.152.198.39:51820"),
						ReplaceAllowedIPs: true,
						AllowedIPs: []net.IPNet{
							wgtest.MustCIDR("192.168.4.10/32"),
							wgtest.MustCIDR("192.168.4.11/32"),
						},
					},
					{
						PublicKey: wgtest.MustHexKey("e818b58db5274087fcc1be5dc728cf53d3b5726b4cef6b9bab8f8f8c2452c25c"),
						Remove:    true,
					},
				},
			},
			attrs: []netlink.Attribute{
				nameAttr,
				{
					Type: wgh.DeviceAPrivateKey,
					Data: keyBytes("e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a"),
				},
				{
					Type: wgh.DeviceAListenPort,
					Data: nlenc.Uint16Bytes(12912),
				},
				{
					Type: wgh.DeviceAFwmark,
					Data: nlenc.Uint32Bytes(0),
				},
				{
					Type: wgh.DeviceAFlags,
					Data: nlenc.Uint32Bytes(wgh.DeviceFReplacePeers),
				},
				{
					Type: wgh.DeviceAPeers,
					Data: nltest.MustMarshalAttributes([]netlink.Attribute{
						{
							Type: 0,
							Data: nltest.MustMarshalAttributes([]netlink.Attribute{
								{
									Type: wgh.PeerAPublicKey,
									Data: keyBytes("b85996fecc9c7f1fc6d2572a76eda11d59bcd20be8e543b15ce4bd85a8e75a33"),
								},
								{
									Type: wgh.PeerAFlags,
									Data: nlenc.Uint32Bytes(wgh.PeerFReplaceAllowedips),
								},
								{
									Type: wgh.PeerAPresharedKey,
									Data: keyBytes("188515093e952f5f22e865cef3012e72f8b5f0b598ac0309d5dacce3b70fcf52"),
								},
								{
									Type: wgh.PeerAEndpoint,
									Data: (*(*[unix.SizeofSockaddrInet6]byte)(unsafe.Pointer(&unix.RawSockaddrInet6{
										Family: unix.AF_INET6,
										Addr: [16]byte{
											0xab, 0xcd, 0x00, 0x23,
											0x00, 0x00, 0x00, 0x00,
											0x00, 0x00, 0x00, 0x00,
											0x00, 0x00, 0x00, 0x33,
										},
										Port: 51820,
									})))[:],
								},
								{
									Type: wgh.PeerAAllowedips,
									Data: mustAllowedIPs([]net.IPNet{
										wgtest.MustCIDR("192.168.4.4/32"),
									}),
								},
							}),
						},
						{
							Type: 1,
							Data: nltest.MustMarshalAttributes([]netlink.Attribute{
								{
									Type: wgh.PeerAPublicKey,
									Data: keyBytes("58402e695ba1772b1cc9309755f043251ea77fdcf10fbe63989ceb7e19321376"),
								},
								{
									Type: wgh.PeerAFlags,
									Data: nlenc.Uint32Bytes(wgh.PeerFReplaceAllowedips),
								},
								{
									Type: wgh.PeerAEndpoint,
									Data: (*(*[unix.SizeofSockaddrInet4]byte)(unsafe.Pointer(&unix.RawSockaddrInet4{
										Family: unix.AF_INET,
										Addr:   [4]byte{182, 122, 22, 19},
										Port:   3233,
									})))[:],
								},
								{
									Type: wgh.PeerAPersistentKeepaliveInterval,
									Data: nlenc.Uint16Bytes(111),
								},
								{
									Type: wgh.PeerAAllowedips,
									Data: mustAllowedIPs([]net.IPNet{
										wgtest.MustCIDR("192.168.4.6/32"),
									}),
								},
							}),
						},

						{
							Type: 2,
							Data: nltest.MustMarshalAttributes([]netlink.Attribute{
								{
									Type: wgh.PeerAPublicKey,
									Data: keyBytes("662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58"),
								},
								{
									Type: wgh.PeerAFlags,
									Data: nlenc.Uint32Bytes(wgh.PeerFReplaceAllowedips),
								},
								{
									Type: wgh.PeerAEndpoint,
									Data: (*(*[unix.SizeofSockaddrInet4]byte)(unsafe.Pointer(&unix.RawSockaddrInet4{
										Family: unix.AF_INET,
										Addr:   [4]byte{5, 152, 198, 39},
										Port:   51820,
									})))[:],
								},
								{
									Type: wgh.PeerAAllowedips,
									Data: mustAllowedIPs([]net.IPNet{
										wgtest.MustCIDR("192.168.4.10/32"),
										wgtest.MustCIDR("192.168.4.11/32"),
									}),
								},
							}),
						},
						{
							Type: 3,
							Data: nltest.MustMarshalAttributes([]netlink.Attribute{
								{
									Type: wgh.PeerAPublicKey,
									Data: keyBytes("e818b58db5274087fcc1be5dc728cf53d3b5726b4cef6b9bab8f8f8c2452c25c"),
								},
								{
									Type: wgh.PeerAFlags,
									Data: nlenc.Uint32Bytes(wgh.PeerFRemoveMe),
								},
							}),
						},
					}),
				},
			},
			ok: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const (
				cmd   = wgh.CmdSetDevice
				flags = netlink.HeaderFlagsRequest | netlink.HeaderFlagsAcknowledge
			)

			fn := func(greq genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
				attrs, err := netlink.UnmarshalAttributes(greq.Data)
				if err != nil {
					return nil, err
				}

				if diff := diffAttrs(tt.attrs, attrs); diff != "" {
					t.Fatalf("unexpected request attributes (-want +got):\n%s", diff)
				}

				// Data currently unused; send a message to acknowledge request.
				return []genetlink.Message{{}}, nil
			}

			c := testClient(t, genltest.CheckRequest(familyID, cmd, flags, fn))
			defer c.Close()

			err := c.ConfigureDevice(okName, tt.cfg)

			if tt.ok && err != nil {
				t.Fatalf("failed to configure device: %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatal("expected an error, but none occurred")
			}
		})
	}
}

func keyBytes(s string) []byte {
	k := wgtest.MustHexKey(s)
	return k[:]
}
