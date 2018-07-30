//+build linux

package wgnl

import (
	"fmt"
	"net"
	"os"
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
		fn   func() ([]net.Interface, error)
		err  error
	}{
		{
			name: "no interfaces",
			fn: func() ([]net.Interface, error) {
				return nil, nil
			},
		},
		{
			name: "no wireguard interfaces",
			fn: func() ([]net.Interface, error) {
				return []net.Interface{{
					Index: 1,
					Name:  "eth0",
				}}, nil
			},
			err: unix.ENOTSUP,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := testClient(t, func(_ genetlink.Message, _ netlink.Message) ([]genetlink.Message, error) {
				return nil, tt.err
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

			c.interfaces = func() ([]net.Interface, error) {
				return []net.Interface{{
					Index: okIndex,
					Name:  okName,
				}}, nil
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
		interfaces func() ([]net.Interface, error)
		msgs       [][]genetlink.Message
		devices    []*wgtypes.Device
	}{
		{
			name: "basic",
			interfaces: func() ([]net.Interface, error) {
				return []net.Interface{
					{
						Index: okIndex,
						Name:  okName,
					},
					{
						Index: 2,
						Name:  "wg1",
					},
				}, nil
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

	c.interfaces = func() ([]net.Interface, error) {
		return []net.Interface{{
			Index: okIndex,
			Name:  okName,
		}}, nil
	}

	return c
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
				Type: wgh.AllowedipAIpaddr,
				Data: ip,
			},
			{
				Type: wgh.AllowedipACidrMask,
				Data: nlenc.Uint8Bytes(uint8(ones)),
			},
			{
				Type: wgh.AllowedipAFamily,
				Data: nlenc.Uint16Bytes(family),
			},
		})

		attrs = append(attrs, netlink.Attribute{
			Type: uint16(i),
			Data: data,
		})
	}

	return nltest.MustMarshalAttributes(attrs)
}

func mustPublicKey() wgtypes.Key {
	priv, err := wgtypes.NewPrivateKey()
	if err != nil {
		panicf("failed to generate private key: %v", err)
	}

	return priv.PublicKey()
}

func panicf(format string, a ...interface{}) {
	panic(fmt.Sprintf(format, a...))
}
