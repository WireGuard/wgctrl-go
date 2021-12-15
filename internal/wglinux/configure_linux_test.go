//go:build linux
// +build linux

package wglinux

import (
	"net"
	"testing"
	"time"
	"unsafe"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/genetlink/genltest"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"github.com/mikioh/ipaddr"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/internal/wgtest"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestLinuxClientConfigureDevice(t *testing.T) {
	nameAttr := netlink.Attribute{
		Type: unix.WGDEVICE_A_IFNAME,
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
						UpdateOnly:                  true,
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
					Type: unix.WGDEVICE_A_PRIVATE_KEY,
					Data: keyBytes("e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a"),
				},
				{
					Type: unix.WGDEVICE_A_LISTEN_PORT,
					Data: nlenc.Uint16Bytes(12912),
				},
				{
					Type: unix.WGDEVICE_A_FWMARK,
					Data: nlenc.Uint32Bytes(0),
				},
				{
					Type: unix.WGDEVICE_A_FLAGS,
					Data: nlenc.Uint32Bytes(unix.WGDEVICE_F_REPLACE_PEERS),
				},
				{
					Type: netlink.Nested | unix.WGDEVICE_A_PEERS,
					Data: m([]netlink.Attribute{
						{
							Type: netlink.Nested,
							Data: m([]netlink.Attribute{
								{
									Type: unix.WGPEER_A_PUBLIC_KEY,
									Data: keyBytes("b85996fecc9c7f1fc6d2572a76eda11d59bcd20be8e543b15ce4bd85a8e75a33"),
								},
								{
									Type: unix.WGPEER_A_FLAGS,
									Data: nlenc.Uint32Bytes(unix.WGPEER_F_REPLACE_ALLOWEDIPS),
								},
								{
									Type: unix.WGPEER_A_PRESHARED_KEY,
									Data: keyBytes("188515093e952f5f22e865cef3012e72f8b5f0b598ac0309d5dacce3b70fcf52"),
								},
								{
									Type: unix.WGPEER_A_ENDPOINT,
									Data: (*(*[unix.SizeofSockaddrInet6]byte)(unsafe.Pointer(&unix.RawSockaddrInet6{
										Family: unix.AF_INET6,
										Addr: [16]byte{
											0xab, 0xcd, 0x00, 0x23,
											0x00, 0x00, 0x00, 0x00,
											0x00, 0x00, 0x00, 0x00,
											0x00, 0x00, 0x00, 0x33,
										},
										Port: sockaddrPort(51820),
									})))[:],
								},
								{
									Type: netlink.Nested | unix.WGPEER_A_ALLOWEDIPS,
									Data: mustAllowedIPs([]net.IPNet{
										wgtest.MustCIDR("192.168.4.4/32"),
									}),
								},
							}...),
						},
						{
							Type: netlink.Nested | 1,
							Data: m([]netlink.Attribute{
								{
									Type: unix.WGPEER_A_PUBLIC_KEY,
									Data: keyBytes("58402e695ba1772b1cc9309755f043251ea77fdcf10fbe63989ceb7e19321376"),
								},
								{
									Type: unix.WGPEER_A_FLAGS,
									Data: nlenc.Uint32Bytes(unix.WGPEER_F_REPLACE_ALLOWEDIPS | unix.WGPEER_F_UPDATE_ONLY),
								},
								{
									Type: unix.WGPEER_A_ENDPOINT,
									Data: (*(*[unix.SizeofSockaddrInet4]byte)(unsafe.Pointer(&unix.RawSockaddrInet4{
										Family: unix.AF_INET,
										Addr:   [4]byte{182, 122, 22, 19},
										Port:   sockaddrPort(3233),
									})))[:],
								},
								{
									Type: unix.WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL,
									Data: nlenc.Uint16Bytes(111),
								},
								{
									Type: netlink.Nested | unix.WGPEER_A_ALLOWEDIPS,
									Data: mustAllowedIPs([]net.IPNet{
										wgtest.MustCIDR("192.168.4.6/32"),
									}),
								},
							}...),
						},
						{
							Type: netlink.Nested | 2,
							Data: m([]netlink.Attribute{
								{
									Type: unix.WGPEER_A_PUBLIC_KEY,
									Data: keyBytes("662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58"),
								},
								{
									Type: unix.WGPEER_A_FLAGS,
									Data: nlenc.Uint32Bytes(unix.WGPEER_F_REPLACE_ALLOWEDIPS),
								},
								{
									Type: unix.WGPEER_A_ENDPOINT,
									Data: (*(*[unix.SizeofSockaddrInet4]byte)(unsafe.Pointer(&unix.RawSockaddrInet4{
										Family: unix.AF_INET,
										Addr:   [4]byte{5, 152, 198, 39},
										Port:   sockaddrPort(51820),
									})))[:],
								},
								{
									Type: netlink.Nested | unix.WGPEER_A_ALLOWEDIPS,
									Data: mustAllowedIPs([]net.IPNet{
										wgtest.MustCIDR("192.168.4.10/32"),
										wgtest.MustCIDR("192.168.4.11/32"),
									}),
								},
							}...),
						},
						{
							Type: netlink.Nested | 3,
							Data: m([]netlink.Attribute{
								{
									Type: unix.WGPEER_A_PUBLIC_KEY,
									Data: keyBytes("e818b58db5274087fcc1be5dc728cf53d3b5726b4cef6b9bab8f8f8c2452c25c"),
								},
								{
									Type: unix.WGPEER_A_FLAGS,
									Data: nlenc.Uint32Bytes(unix.WGPEER_F_REMOVE_ME),
								},
							}...),
						},
					}...),
				},
			},
			ok: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const (
				cmd   = unix.WG_CMD_SET_DEVICE
				flags = netlink.Request | netlink.Acknowledge
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

func TestLinuxClientConfigureDeviceLargePeerIPChunks(t *testing.T) {
	nameAttr := netlink.Attribute{
		Type: unix.WGDEVICE_A_IFNAME,
		Data: nlenc.Bytes(okName),
	}

	var (
		peerA    = wgtest.MustPublicKey()
		peerAIPs = generateIPs(ipBatchChunk + 1)

		peerB    = wgtest.MustPublicKey()
		peerBIPs = generateIPs(ipBatchChunk / 2)

		peerC    = wgtest.MustPublicKey()
		peerCIPs = generateIPs(ipBatchChunk * 3)

		peerD = wgtest.MustPublicKey()
	)

	cfg := wgtypes.Config{
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:         peerA,
				UpdateOnly:        true,
				ReplaceAllowedIPs: true,

				AllowedIPs: peerAIPs,
			},
			{
				PublicKey:         peerB,
				UpdateOnly:        true,
				ReplaceAllowedIPs: true,
				AllowedIPs:        peerBIPs,
			},
			{
				PublicKey:         peerC,
				UpdateOnly:        true,
				ReplaceAllowedIPs: true,
				AllowedIPs:        peerCIPs,
			},
			{
				PublicKey: peerD,
				Remove:    true,
			},
		},
	}

	var allAttrs []netlink.Attribute
	fn := func(greq genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
		attrs, err := netlink.UnmarshalAttributes(greq.Data)
		if err != nil {
			return nil, err
		}

		allAttrs = append(allAttrs, attrs...)

		// Data currently unused; send a message to acknowledge request.
		return []genetlink.Message{{}}, nil
	}

	c := testClient(t, fn)
	defer c.Close()

	if err := c.ConfigureDevice(okName, cfg); err != nil {
		t.Fatalf("failed to configure: %v", err)
	}

	want := []netlink.Attribute{
		// First peer, first chunk.
		nameAttr,
		{
			Type: unix.WGDEVICE_A_FLAGS,
			Data: nlenc.Uint32Bytes(unix.WGDEVICE_F_REPLACE_PEERS),
		},
		{
			Type: netlink.Nested | unix.WGDEVICE_A_PEERS,
			Data: m(netlink.Attribute{
				Type: netlink.Nested,
				Data: m([]netlink.Attribute{
					{
						Type: unix.WGPEER_A_PUBLIC_KEY,
						Data: peerA[:],
					},
					{
						Type: unix.WGPEER_A_FLAGS,
						Data: nlenc.Uint32Bytes(unix.WGPEER_F_REPLACE_ALLOWEDIPS | unix.WGPEER_F_UPDATE_ONLY),
					},
					{
						Type: netlink.Nested | unix.WGPEER_A_ALLOWEDIPS,
						Data: mustAllowedIPs(peerAIPs[:ipBatchChunk]),
					},
				}...),
			}),
		},
		// First peer, final chunk.
		nameAttr,
		{
			Type: netlink.Nested | unix.WGDEVICE_A_PEERS,
			Data: m(netlink.Attribute{
				Type: netlink.Nested,
				Data: m([]netlink.Attribute{
					{
						Type: unix.WGPEER_A_PUBLIC_KEY,
						Data: peerA[:],
					},
					{
						Type: unix.WGPEER_A_FLAGS,
						Data: nlenc.Uint32Bytes(unix.WGPEER_F_UPDATE_ONLY),
					},
					// Not first chunk; don't replace IPs.
					{
						Type: netlink.Nested | unix.WGPEER_A_ALLOWEDIPS,
						Data: mustAllowedIPs(peerAIPs[ipBatchChunk:]),
					},
				}...),
			}),
		},
		// Second peer, only chunk.
		nameAttr,
		// This is not the first peer; don't replace existing peers.
		{
			Type: netlink.Nested | unix.WGDEVICE_A_PEERS,
			Data: m(netlink.Attribute{
				Type: netlink.Nested,
				Data: m([]netlink.Attribute{
					{
						Type: unix.WGPEER_A_PUBLIC_KEY,
						Data: peerB[:],
					},
					{
						Type: unix.WGPEER_A_FLAGS,
						Data: nlenc.Uint32Bytes(unix.WGPEER_F_REPLACE_ALLOWEDIPS | unix.WGPEER_F_UPDATE_ONLY),
					},
					{
						Type: netlink.Nested | unix.WGPEER_A_ALLOWEDIPS,
						Data: mustAllowedIPs(peerBIPs),
					},
				}...),
			}),
		},
		// Third peer, first chunk.
		nameAttr,
		// This is not the first peer; don't replace existing peers.
		{
			Type: netlink.Nested | unix.WGDEVICE_A_PEERS,
			Data: m(netlink.Attribute{
				Type: netlink.Nested,
				Data: m([]netlink.Attribute{
					{
						Type: unix.WGPEER_A_PUBLIC_KEY,
						Data: peerC[:],
					},
					{
						Type: unix.WGPEER_A_FLAGS,
						Data: nlenc.Uint32Bytes(unix.WGPEER_F_REPLACE_ALLOWEDIPS | unix.WGPEER_F_UPDATE_ONLY),
					},
					{
						Type: netlink.Nested | unix.WGPEER_A_ALLOWEDIPS,
						Data: mustAllowedIPs(peerCIPs[:ipBatchChunk]),
					},
				}...),
			}),
		},
		// Third peer, second chunk.
		nameAttr,
		{
			Type: netlink.Nested | unix.WGDEVICE_A_PEERS,
			Data: m(netlink.Attribute{
				Type: netlink.Nested,
				Data: m([]netlink.Attribute{
					{
						Type: unix.WGPEER_A_PUBLIC_KEY,
						Data: peerC[:],
					},
					{
						Type: unix.WGPEER_A_FLAGS,
						Data: nlenc.Uint32Bytes(unix.WGPEER_F_UPDATE_ONLY),
					},
					// Not first chunk; don't replace IPs.
					{
						Type: netlink.Nested | unix.WGPEER_A_ALLOWEDIPS,
						Data: mustAllowedIPs(peerCIPs[ipBatchChunk : ipBatchChunk*2]),
					},
				}...),
			}),
		},
		// Third peer, final chunk.
		nameAttr,
		{
			Type: netlink.Nested | unix.WGDEVICE_A_PEERS,
			Data: m(netlink.Attribute{
				Type: netlink.Nested,
				Data: m([]netlink.Attribute{
					{
						Type: unix.WGPEER_A_PUBLIC_KEY,
						Data: peerC[:],
					},
					{
						Type: unix.WGPEER_A_FLAGS,
						Data: nlenc.Uint32Bytes(unix.WGPEER_F_UPDATE_ONLY),
					},
					// Not first chunk; don't replace IPs.
					{
						Type: netlink.Nested | unix.WGPEER_A_ALLOWEDIPS,
						Data: mustAllowedIPs(peerCIPs[ipBatchChunk*2:]),
					},
				}...),
			}),
		},
		// Fourth peer, only chunk.
		nameAttr,
		{
			Type: netlink.Nested | unix.WGDEVICE_A_PEERS,
			Data: m(netlink.Attribute{
				Type: netlink.Nested,
				Data: m([]netlink.Attribute{
					{
						Type: unix.WGPEER_A_PUBLIC_KEY,
						Data: peerD[:],
					},
					// Not first chunk; don't replace IPs.
					{
						Type: unix.WGPEER_A_FLAGS,
						Data: nlenc.Uint32Bytes(unix.WGPEER_F_REMOVE_ME),
					},
				}...),
			}),
		},
	}

	if diff := diffAttrs(want, allAttrs); diff != "" {
		t.Fatalf("unexpected final attributes (-want +got):\n%s", diff)
	}
}

func keyBytes(s string) []byte {
	k := wgtest.MustHexKey(s)
	return k[:]
}

func generateIPs(n int) []net.IPNet {
	cur, err := ipaddr.Parse("2001:db8::/64")
	if err != nil {
		panicf("failed to create cursor: %v", err)
	}

	ips := make([]net.IPNet, 0, n)
	for i := 0; i < n; i++ {
		pos := cur.Next()
		if pos == nil {
			panic("hit nil IP during IP generation")
		}

		ips = append(ips, net.IPNet{
			IP:   pos.IP,
			Mask: net.CIDRMask(128, 128),
		})
	}

	return ips
}
