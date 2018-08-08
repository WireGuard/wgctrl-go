//+build linux

package wgnl

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/google/go-cmp/cmp"
	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/genetlink/genltest"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"github.com/mdlayher/netlink/nltest"
	"github.com/mdlayher/wireguardctrl/internal/wgnl/internal/wgh"
	"github.com/mdlayher/wireguardctrl/wgtypes"
	"golang.org/x/sys/unix"
)

func TestLinuxClientDevicesEmpty(t *testing.T) {
	tests := []struct {
		name string
		fn   func() ([]string, error)
	}{
		{
			name: "no interfaces",
			fn: func() ([]string, error) {
				return nil, nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := testClient(t, func(_ genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
				panic("no devices; shouldn't call genetlink")
			})
			defer c.Close()

			c.interfaces = tt.fn

			ds, err := c.Devices()
			if err != nil {
				t.Fatalf("failed to get devices: %v", err)
			}

			if diff := cmp.Diff(0, len(ds)); diff != "" {
				t.Fatalf("unexpected number of devices (-want +got):\n%s", diff)
			}
		})
	}
}

func TestLinuxClientIsNotExist(t *testing.T) {
	byIndex := func(c *client) error {
		_, err := c.DeviceByIndex(1)
		return err
	}

	byName := func(c *client) error {
		_, err := c.DeviceByName("wg0")
		return err
	}

	configure := func(c *client) error {
		return c.ConfigureDevice("wg0", wgtypes.Config{})
	}

	tests := []struct {
		name string
		fn   func(c *client) error
		msgs []genetlink.Message
		err  error
	}{
		{
			name: "index: 0",
			fn: func(c *client) error {
				_, err := c.DeviceByIndex(0)
				return err
			},
		},
		{
			name: "name: empty",
			fn: func(c *client) error {
				_, err := c.DeviceByName("")
				return err
			},
		},
		{
			name: "index: ENODEV",
			fn:   byIndex,
			err:  unix.ENODEV,
		},
		{
			name: "index: ENOTSUP",
			fn:   byIndex,
			err:  unix.ENOTSUP,
		},
		{
			name: "name: ENODEV",
			fn:   byName,
			err:  unix.ENODEV,
		},
		{
			name: "name: ENOTSUP",
			fn:   byName,
			err:  unix.ENOTSUP,
		},
		{
			name: "configure: ENODEV",
			fn:   configure,
			err:  unix.ENODEV,
		},
		{
			name: "configure: ENOTSUP",
			fn:   configure,
			err:  unix.ENOTSUP,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := testClient(t, func(_ genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
				return tt.msgs, tt.err
			})
			defer c.Close()

			if err := tt.fn(c); !os.IsNotExist(err) {
				t.Fatalf("expected is not exist, but got: %v", err)
			}
		})
	}
}

func TestLinuxClientDevicesError(t *testing.T) {
	tests := []struct {
		name string
		msgs []genetlink.Message
	}{
		{
			name: "bad peer endpoint",
			msgs: []genetlink.Message{{
				Data: nltest.MustMarshalAttributes([]netlink.Attribute{{
					Type: wgh.DeviceAPeers,
					Data: nltest.MustMarshalAttributes([]netlink.Attribute{{
						Type: 0,
						Data: nltest.MustMarshalAttributes([]netlink.Attribute{
							{
								Type: wgh.PeerAEndpoint,
								Data: []byte{0xff},
							},
						}),
					}}),
				}}),
			}},
		},
		{
			name: "bad peer last handshake time",
			msgs: []genetlink.Message{{
				Data: nltest.MustMarshalAttributes([]netlink.Attribute{{
					Type: wgh.DeviceAPeers,
					Data: nltest.MustMarshalAttributes([]netlink.Attribute{{
						Type: 0,
						Data: nltest.MustMarshalAttributes([]netlink.Attribute{
							{
								Type: wgh.PeerALastHandshakeTime,
								Data: []byte{0xff},
							},
						}),
					}}),
				}}),
			}},
		},
		{
			name: "bad peer allowed IPs IP",
			msgs: []genetlink.Message{{
				Data: nltest.MustMarshalAttributes([]netlink.Attribute{{
					Type: wgh.DeviceAPeers,
					Data: nltest.MustMarshalAttributes([]netlink.Attribute{{
						Type: 0,
						Data: nltest.MustMarshalAttributes([]netlink.Attribute{
							{
								Type: wgh.PeerAAllowedips,
								Data: nltest.MustMarshalAttributes([]netlink.Attribute{{
									Type: 0,
									Data: nltest.MustMarshalAttributes([]netlink.Attribute{{
										Type: wgh.AllowedipAIpaddr,
										Data: []byte{0xff},
									}}),
								}}),
							},
						}),
					}}),
				}}),
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := testClient(t, func(_ genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
				return tt.msgs, nil
			})
			defer c.Close()

			c.interfaces = func() ([]string, error) {
				return []string{okName}, nil
			}

			if _, err := c.Devices(); err == nil {
				t.Fatal("expected an error, but none occurred")
			}
		})
	}
}

const (
	okIndex = 1
	okName  = "wg0"
)

func TestLinuxClientDevicesOK(t *testing.T) {
	const (
		testIndex = 2
		testName  = "wg1"
	)

	var (
		testKey wgtypes.Key
		keyA    = mustPublicKey()
		keyB    = mustPublicKey()
		keyC    = mustPublicKey()
	)

	testKey[0] = 0xff

	tests := []struct {
		name       string
		interfaces func() ([]string, error)
		msgs       [][]genetlink.Message
		devices    []*wgtypes.Device
	}{
		{
			name: "basic",
			interfaces: func() ([]string, error) {
				return []string{okName, "wg1"}, nil
			},
			msgs: [][]genetlink.Message{
				{{
					Data: nltest.MustMarshalAttributes([]netlink.Attribute{
						{
							Type: wgh.DeviceAIfindex,
							Data: nlenc.Uint32Bytes(okIndex),
						},
						{
							Type: wgh.DeviceAIfname,
							Data: nlenc.Bytes(okName),
						},
					}),
				}},
				{{
					Data: nltest.MustMarshalAttributes([]netlink.Attribute{
						{
							Type: wgh.DeviceAIfindex,
							Data: nlenc.Uint32Bytes(testIndex),
						},
						{
							Type: wgh.DeviceAIfname,
							Data: nlenc.Bytes(testName),
						},
					}),
				}},
			},
			devices: []*wgtypes.Device{
				{
					Name: okName,
				},
				{
					Name: "wg1",
				},
			},
		},
		{
			name: "complete",
			msgs: [][]genetlink.Message{{{
				Data: nltest.MustMarshalAttributes([]netlink.Attribute{
					{
						Type: wgh.DeviceAIfindex,
						Data: nlenc.Uint32Bytes(okIndex),
					},
					{
						Type: wgh.DeviceAIfname,
						Data: nlenc.Bytes(okName),
					},
					{
						Type: wgh.DeviceAPrivateKey,
						Data: testKey[:],
					},
					{
						Type: wgh.DeviceAPublicKey,
						Data: testKey[:],
					},
					{
						Type: wgh.DeviceAListenPort,
						Data: nlenc.Uint16Bytes(5555),
					},
					{
						Type: wgh.DeviceAFwmark,
						Data: nlenc.Uint32Bytes(0xff),
					},
					{
						Type: wgh.DeviceAPeers,
						Data: nltest.MustMarshalAttributes([]netlink.Attribute{
							{
								Type: 0,
								Data: nltest.MustMarshalAttributes([]netlink.Attribute{
									{
										Type: wgh.PeerAPublicKey,
										Data: testKey[:],
									},
									{
										Type: wgh.PeerAPresharedKey,
										Data: testKey[:],
									},
									{
										Type: wgh.PeerAEndpoint,
										Data: (*(*[unix.SizeofSockaddrInet4]byte)(unsafe.Pointer(&unix.RawSockaddrInet4{
											Addr: [4]byte{192, 168, 1, 1},
											Port: 1111,
										})))[:],
									},
									{
										Type: wgh.PeerAPersistentKeepaliveInterval,
										Data: nlenc.Uint16Bytes(10),
									},
									{
										Type: wgh.PeerALastHandshakeTime,
										Data: (*(*[sizeofTimespec]byte)(unsafe.Pointer(&unix.Timespec{
											Sec:  10,
											Nsec: 20,
										})))[:],
									},
									{
										Type: wgh.PeerARxBytes,
										Data: nlenc.Uint64Bytes(100),
									},
									{
										Type: wgh.PeerATxBytes,
										Data: nlenc.Uint64Bytes(200),
									},
									{
										Type: wgh.PeerAAllowedips,
										Data: mustAllowedIPs([]net.IPNet{
											mustCIDR("192.168.1.10/32"),
											mustCIDR("fd00::1/128"),
										}),
									},
								}),
							},
							// "dummy" peer with only necessary fields to verify
							// multi-peer parsing logic and IPv4/IPv6 parsing.
							{
								Type: 1,
								Data: nltest.MustMarshalAttributes([]netlink.Attribute{
									{
										Type: wgh.PeerAPublicKey,
										Data: testKey[:],
									},
									{
										Type: wgh.PeerAEndpoint,
										Data: (*(*[unix.SizeofSockaddrInet6]byte)(unsafe.Pointer(&unix.RawSockaddrInet6{
											Addr: [16]byte{
												0xfe, 0x80, 0x00, 0x00,
												0x00, 0x00, 0x00, 0x00,
												0x00, 0x00, 0x00, 0x00,
												0x00, 0x00, 0x00, 0x01,
											},
											Port: 2222,
										})))[:],
									},
								}),
							},
						}),
					},
				}),
			}}},
			devices: []*wgtypes.Device{
				{
					Name:         okName,
					PrivateKey:   testKey,
					PublicKey:    testKey,
					ListenPort:   5555,
					FirewallMark: 0xff,
					Peers: []wgtypes.Peer{
						{
							PublicKey:    testKey,
							PresharedKey: testKey,
							Endpoint: &net.UDPAddr{
								IP:   net.IPv4(192, 168, 1, 1),
								Port: 1111,
							},
							PersistentKeepaliveInterval: 10 * time.Second,
							LastHandshakeTime:           time.Unix(10, 20),
							ReceiveBytes:                100,
							TransmitBytes:               200,
							AllowedIPs: []net.IPNet{
								mustCIDR("192.168.1.10/32"),
								mustCIDR("fd00::1/128"),
							},
						},
						{
							PublicKey: testKey,
							Endpoint: &net.UDPAddr{
								IP:   net.ParseIP("fe80::1"),
								Port: 2222,
							},
						},
					},
				},
			},
		},
		{
			name: "merge devices",
			msgs: [][]genetlink.Message{{
				// The "target" device.
				{
					Data: nltest.MustMarshalAttributes([]netlink.Attribute{
						{
							Type: wgh.DeviceAIfname,
							Data: nlenc.Bytes(okName),
						},
						{
							Type: wgh.DeviceAPrivateKey,
							Data: testKey[:],
						},
						{
							Type: wgh.DeviceAPeers,
							Data: nltest.MustMarshalAttributes([]netlink.Attribute{
								{
									Type: 0,
									Data: nltest.MustMarshalAttributes([]netlink.Attribute{
										{
											Type: wgh.PeerAPublicKey,
											Data: keyA[:],
										},
										{
											Type: wgh.PeerAAllowedips,
											Data: mustAllowedIPs([]net.IPNet{
												mustCIDR("192.168.1.10/32"),
												mustCIDR("192.168.1.11/32"),
											}),
										},
									}),
								},
							}),
						},
					}),
				},
				// Continuation of first peer list, new peer list.
				{
					Data: nltest.MustMarshalAttributes([]netlink.Attribute{
						{
							Type: wgh.DeviceAPeers,
							Data: nltest.MustMarshalAttributes([]netlink.Attribute{
								{
									Type: 0,
									Data: nltest.MustMarshalAttributes([]netlink.Attribute{
										{
											Type: wgh.PeerAPublicKey,
											Data: keyA[:],
										},
										{
											Type: wgh.PeerAAllowedips,
											Data: mustAllowedIPs([]net.IPNet{
												mustCIDR("fd00:dead:beef:dead::/64"),
												mustCIDR("fd00:dead:beef:ffff::/64"),
											}),
										},
									}),
								},
								{
									Type: 1,
									Data: nltest.MustMarshalAttributes([]netlink.Attribute{
										{
											Type: wgh.PeerAPublicKey,
											Data: keyB[:],
										},
										{
											Type: wgh.PeerAAllowedips,
											Data: mustAllowedIPs([]net.IPNet{
												mustCIDR("10.10.10.0/24"),
												mustCIDR("10.10.11.0/24"),
											}),
										},
									}),
								},
							}),
						},
					}),
				},
				// Continuation of prevoius peer list, new peer list.
				{
					Data: nltest.MustMarshalAttributes([]netlink.Attribute{
						{
							Type: wgh.DeviceAPeers,
							Data: nltest.MustMarshalAttributes([]netlink.Attribute{
								{
									Type: 0,
									Data: nltest.MustMarshalAttributes([]netlink.Attribute{
										{
											Type: wgh.PeerAPublicKey,
											Data: keyB[:],
										},
										{
											Type: wgh.PeerAAllowedips,
											Data: mustAllowedIPs([]net.IPNet{
												mustCIDR("10.10.12.0/24"),
												mustCIDR("10.10.13.0/24"),
											}),
										},
									}),
								},
								{
									Type: 1,
									Data: nltest.MustMarshalAttributes([]netlink.Attribute{
										{
											Type: wgh.PeerAPublicKey,
											Data: keyC[:],
										},
										{
											Type: wgh.PeerAAllowedips,
											Data: mustAllowedIPs([]net.IPNet{
												mustCIDR("fd00:1234::/32"),
												mustCIDR("fd00:4567::/32"),
											}),
										},
									}),
								},
							}),
						},
					}),
				},
			}},
			devices: []*wgtypes.Device{
				{
					Name:       okName,
					PrivateKey: testKey,
					Peers: []wgtypes.Peer{
						{
							PublicKey: keyA,
							AllowedIPs: []net.IPNet{
								mustCIDR("192.168.1.10/32"),
								mustCIDR("192.168.1.11/32"),
								mustCIDR("fd00:dead:beef:dead::/64"),
								mustCIDR("fd00:dead:beef:ffff::/64"),
							},
						},
						{
							PublicKey: keyB,
							AllowedIPs: []net.IPNet{
								mustCIDR("10.10.10.0/24"),
								mustCIDR("10.10.11.0/24"),
								mustCIDR("10.10.12.0/24"),
								mustCIDR("10.10.13.0/24"),
							},
						},
						{
							PublicKey: keyC,
							AllowedIPs: []net.IPNet{
								mustCIDR("fd00:1234::/32"),
								mustCIDR("fd00:4567::/32"),
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const (
				cmd   = wgh.CmdGetDevice
				flags = netlink.HeaderFlagsRequest | netlink.HeaderFlagsDump
			)

			// Advance through the test messages on subsequent calls.
			var i int
			fn := func(_ genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
				defer func() { i++ }()

				return tt.msgs[i], nil
			}

			c := testClient(t, genltest.CheckRequest(familyID, cmd, flags, fn))
			defer c.Close()

			// Replace interfaces if necessary.
			if tt.interfaces != nil {
				c.interfaces = tt.interfaces
			}

			devices, err := c.Devices()
			if err != nil {
				t.Fatalf("failed to get devices: %v", err)
			}

			if diff := cmp.Diff(tt.devices, devices); diff != "" {
				t.Fatalf("unexpected devices (-want +got):\n%s", diff)
			}
		})
	}
}

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
				PrivateKey:   keyPtr(mustHexKey("e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a")),
				ListenPort:   intPtr(12912),
				FirewallMark: intPtr(0),
				ReplacePeers: true,
				Peers: []wgtypes.PeerConfig{
					{
						PublicKey:         mustHexKey("b85996fecc9c7f1fc6d2572a76eda11d59bcd20be8e543b15ce4bd85a8e75a33"),
						PresharedKey:      keyPtr(mustHexKey("188515093e952f5f22e865cef3012e72f8b5f0b598ac0309d5dacce3b70fcf52")),
						Endpoint:          mustUDPAddr("[abcd:23::33%2]:51820"),
						ReplaceAllowedIPs: true,
						AllowedIPs: []net.IPNet{
							mustCIDR("192.168.4.4/32"),
						},
					},
					{
						PublicKey:                   mustHexKey("58402e695ba1772b1cc9309755f043251ea77fdcf10fbe63989ceb7e19321376"),
						Endpoint:                    mustUDPAddr("182.122.22.19:3233"),
						PersistentKeepaliveInterval: durPtr(111 * time.Second),
						ReplaceAllowedIPs:           true,
						AllowedIPs: []net.IPNet{
							mustCIDR("192.168.4.6/32"),
						},
					},
					{
						PublicKey:         mustHexKey("662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58"),
						Endpoint:          mustUDPAddr("5.152.198.39:51820"),
						ReplaceAllowedIPs: true,
						AllowedIPs: []net.IPNet{
							mustCIDR("192.168.4.10/32"),
							mustCIDR("192.168.4.11/32"),
						},
					},
					{
						PublicKey: mustHexKey("e818b58db5274087fcc1be5dc728cf53d3b5726b4cef6b9bab8f8f8c2452c25c"),
						Remove:    true,
					},
				},
			},
			attrs: []netlink.Attribute{
				nameAttr,
				{
					Type: wgh.DeviceAPrivateKey,
					Data: keyBytes(mustHexKey("e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a")),
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
									Data: keyBytes(mustHexKey("b85996fecc9c7f1fc6d2572a76eda11d59bcd20be8e543b15ce4bd85a8e75a33")),
								},
								{
									Type: wgh.PeerAFlags,
									Data: nlenc.Uint32Bytes(wgh.PeerFReplaceAllowedips),
								},
								{
									Type: wgh.PeerAPresharedKey,
									Data: keyBytes(mustHexKey("188515093e952f5f22e865cef3012e72f8b5f0b598ac0309d5dacce3b70fcf52")),
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
										mustCIDR("192.168.4.4/32"),
									}),
								},
							}),
						},
						{
							Type: 1,
							Data: nltest.MustMarshalAttributes([]netlink.Attribute{
								{
									Type: wgh.PeerAPublicKey,
									Data: keyBytes(mustHexKey("58402e695ba1772b1cc9309755f043251ea77fdcf10fbe63989ceb7e19321376")),
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
										mustCIDR("192.168.4.6/32"),
									}),
								},
							}),
						},

						{
							Type: 2,
							Data: nltest.MustMarshalAttributes([]netlink.Attribute{
								{
									Type: wgh.PeerAPublicKey,
									Data: keyBytes(mustHexKey("662e14fd594556f522604703340351258903b64f35553763f19426ab2a515c58")),
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
										mustCIDR("192.168.4.10/32"),
										mustCIDR("192.168.4.11/32"),
									}),
								},
							}),
						},
						{
							Type: 3,
							Data: nltest.MustMarshalAttributes([]netlink.Attribute{
								{
									Type: wgh.PeerAPublicKey,
									Data: keyBytes(mustHexKey("e818b58db5274087fcc1be5dc728cf53d3b5726b4cef6b9bab8f8f8c2452c25c")),
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

func Test_parseRTNLInterfaces(t *testing.T) {
	// marshalAttrs creates packed netlink attributes with a prepended ifinfomsg
	// structure, as returned by rtnetlink.
	marshalAttrs := func(attrs []netlink.Attribute) []byte {
		ifinfomsg := make([]byte, syscall.SizeofIfInfomsg)

		return append(ifinfomsg, nltest.MustMarshalAttributes(attrs)...)
	}

	tests := []struct {
		name string
		msgs []syscall.NetlinkMessage
		ifis []string
		ok   bool
	}{
		{
			name: "short ifinfomsg",
			msgs: []syscall.NetlinkMessage{{
				Header: syscall.NlMsghdr{
					Type: unix.RTM_NEWLINK,
				},
				Data: []byte{0xff},
			}},
		},
		{
			name: "empty",
			ok:   true,
		},
		{
			name: "immediate done",
			msgs: []syscall.NetlinkMessage{{
				Header: syscall.NlMsghdr{
					Type: unix.NLMSG_DONE,
				},
			}},
			ok: true,
		},
		{
			name: "ok",
			msgs: []syscall.NetlinkMessage{
				// Bridge device.
				{
					Header: syscall.NlMsghdr{
						Type: unix.RTM_NEWLINK,
					},
					Data: marshalAttrs([]netlink.Attribute{
						{
							Type: unix.IFLA_IFNAME,
							Data: nlenc.Bytes("br0"),
						},
						{
							Type: unix.IFLA_LINKINFO,
							Data: nltest.MustMarshalAttributes([]netlink.Attribute{{
								Type: unix.IFLA_INFO_KIND,
								Data: nlenc.Bytes("bridge"),
							}}),
						},
					}),
				},
				// WireGuard device.
				{
					Header: syscall.NlMsghdr{
						Type: unix.RTM_NEWLINK,
					},
					Data: marshalAttrs([]netlink.Attribute{
						{
							Type: unix.IFLA_IFNAME,
							Data: nlenc.Bytes(okName),
						},
						{
							Type: unix.IFLA_LINKINFO,
							Data: nltest.MustMarshalAttributes([]netlink.Attribute{
								// Random junk to skip.
								{
									Type: 255,
									Data: nlenc.Uint16Bytes(0xff),
								},
								{
									Type: unix.IFLA_INFO_KIND,
									Data: nlenc.Bytes(wgKind),
								},
							}),
						},
					}),
				},
			},
			ifis: []string{okName},
			ok:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ifis, err := parseRTNLInterfaces(tt.msgs)

			if tt.ok && err != nil {
				t.Fatalf("failed to parse interfaces: %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatal("expected an error, but none occurred")
			}
			if err != nil {
				return
			}

			if diff := cmp.Diff(tt.ifis, ifis); diff != "" {
				t.Fatalf("unexpected interfaces (-want +got):\n%s", diff)
			}
		})
	}
}

const familyID = 20

func testClient(t *testing.T, fn genltest.Func) *client {
	family := genetlink.Family{
		ID:      familyID,
		Version: wgh.GenlVersion,
		Name:    wgh.GenlName,
	}

	conn := genltest.Dial(genltest.ServeFamily(family, fn))

	c, err := initClient(conn)
	if err != nil {
		t.Fatalf("failed to open client: %v", err)
	}

	c.interfaces = func() ([]string, error) {
		return []string{okName}, nil
	}

	return c
}

func diffAttrs(x, y []netlink.Attribute) string {
	// Make copies to avoid a race and then zero out length values
	// for comparison.
	xPrime := make([]netlink.Attribute, len(x))
	copy(xPrime, x)

	for i := 0; i < len(xPrime); i++ {
		xPrime[i].Length = 0
	}

	yPrime := make([]netlink.Attribute, len(y))
	copy(yPrime, y)

	for i := 0; i < len(yPrime); i++ {
		yPrime[i].Length = 0
	}

	return cmp.Diff(xPrime, yPrime)
}

func mustCIDR(s string) net.IPNet {
	_, cidr, err := net.ParseCIDR(s)
	if err != nil {
		panicf("failed to parse CIDR: %v", err)
	}

	return *cidr
}

func mustAllowedIPs(ipns []net.IPNet) []byte {
	var attrs []netlink.Attribute
	for i, ipn := range ipns {
		var (
			ip     = ipn.IP
			family = uint16(unix.AF_INET6)
		)

		if ip4 := ip.To4(); ip4 != nil {
			ip = ip4
			family = unix.AF_INET
		}

		ones, _ := ipn.Mask.Size()

		data := nltest.MustMarshalAttributes([]netlink.Attribute{
			{
				Type: wgh.AllowedipAFamily,
				Data: nlenc.Uint16Bytes(family),
			},
			{
				Type: wgh.AllowedipAIpaddr,
				Data: ip,
			},
			{
				Type: wgh.AllowedipACidrMask,
				Data: nlenc.Uint8Bytes(uint8(ones)),
			},
		})

		attrs = append(attrs, netlink.Attribute{
			Type: uint16(i),
			Data: data,
		})
	}

	return nltest.MustMarshalAttributes(attrs)
}

func mustPrivateKey() wgtypes.Key {
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		panicf("failed to generate private key: %v", err)
	}

	return k
}

func mustPublicKey() wgtypes.Key {
	return mustPrivateKey().PublicKey()
}

func intPtr(v int) *int {
	return &v
}

func panicf(format string, a ...interface{}) {
	panic(fmt.Sprintf(format, a...))
}

func durPtr(d time.Duration) *time.Duration {
	return &d
}

func keyPtr(k wgtypes.Key) *wgtypes.Key {
	return &k
}

func keyBytes(k wgtypes.Key) []byte {
	return k[:]
}

func mustHexKey(s string) wgtypes.Key {
	b, err := hex.DecodeString(s)
	if err != nil {
		panicf("failed to decode hex key: %v", err)
	}

	k, err := wgtypes.NewKey(b)
	if err != nil {
		panicf("failed to create key: %v", err)
	}

	return k
}

func mustUDPAddr(s string) *net.UDPAddr {
	a, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		panicf("failed to resolve UDP address: %v", err)
	}

	return a
}
