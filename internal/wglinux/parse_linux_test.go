//go:build linux
// +build linux

package wglinux

import (
	"net"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"github.com/google/go-cmp/cmp"
	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/genetlink/genltest"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/internal/wgtest"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestLinuxClientDevicesError(t *testing.T) {
	tests := []struct {
		name string
		msgs []genetlink.Message
	}{
		{
			name: "bad peer endpoint",
			msgs: []genetlink.Message{{
				Data: m(netlink.Attribute{
					Type: unix.WGDEVICE_A_PEERS,
					Data: m(netlink.Attribute{
						Type: 0,
						Data: m(netlink.Attribute{
							Type: unix.WGPEER_A_ENDPOINT,
							Data: []byte{0xff},
						}),
					}),
				}),
			}},
		},
		{
			name: "bad peer last handshake time",
			msgs: []genetlink.Message{{
				Data: m(netlink.Attribute{
					Type: unix.WGDEVICE_A_PEERS,
					Data: m(netlink.Attribute{
						Type: 0,
						Data: m(netlink.Attribute{
							Type: unix.WGPEER_A_LAST_HANDSHAKE_TIME,
							Data: []byte{0xff},
						}),
					}),
				}),
			}},
		},
		{
			name: "bad peer allowed IPs IP",
			msgs: []genetlink.Message{{
				Data: m(netlink.Attribute{
					Type: unix.WGDEVICE_A_PEERS,
					Data: m(netlink.Attribute{
						Type: 0,
						Data: m(netlink.Attribute{
							Type: unix.WGPEER_A_ALLOWEDIPS,
							Data: m(netlink.Attribute{
								Type: 0,
								Data: m(netlink.Attribute{
									Type: unix.WGALLOWEDIP_A_IPADDR,
									Data: []byte{0xff},
								}),
							}),
						}),
					}),
				}),
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

func TestLinuxClientDevicesOK(t *testing.T) {
	const (
		testIndex = 2
		testName  = "wg1"
	)

	var (
		testKey wgtypes.Key
		keyA    = wgtest.MustPublicKey()
		keyB    = wgtest.MustPublicKey()
		keyC    = wgtest.MustPublicKey()
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
					Data: m([]netlink.Attribute{
						{
							Type: unix.WGDEVICE_A_IFINDEX,
							Data: nlenc.Uint32Bytes(okIndex),
						},
						{
							Type: unix.WGDEVICE_A_IFNAME,
							Data: nlenc.Bytes(okName),
						},
					}...),
				}},
				{{
					Data: m([]netlink.Attribute{
						{
							Type: unix.WGDEVICE_A_IFINDEX,
							Data: nlenc.Uint32Bytes(testIndex),
						},
						{
							Type: unix.WGDEVICE_A_IFNAME,
							Data: nlenc.Bytes(testName),
						},
					}...),
				}},
			},
			devices: []*wgtypes.Device{
				{
					Name: okName,
					Type: wgtypes.LinuxKernel,
				},
				{
					Name: "wg1",
					Type: wgtypes.LinuxKernel,
				},
			},
		},
		{
			name: "complete",
			msgs: [][]genetlink.Message{{{
				Data: m([]netlink.Attribute{
					{
						Type: unix.WGDEVICE_A_IFINDEX,
						Data: nlenc.Uint32Bytes(okIndex),
					},
					{
						Type: unix.WGDEVICE_A_IFNAME,
						Data: nlenc.Bytes(okName),
					},
					{
						Type: unix.WGDEVICE_A_PRIVATE_KEY,
						Data: testKey[:],
					},
					{
						Type: unix.WGDEVICE_A_PUBLIC_KEY,
						Data: testKey[:],
					},
					{
						Type: unix.WGDEVICE_A_LISTEN_PORT,
						Data: nlenc.Uint16Bytes(5555),
					},
					{
						Type: unix.WGDEVICE_A_FWMARK,
						Data: nlenc.Uint32Bytes(0xff),
					},
					{
						Type: unix.WGDEVICE_A_PEERS,
						Data: m([]netlink.Attribute{
							{
								Type: 0,
								Data: m([]netlink.Attribute{
									{
										Type: unix.WGPEER_A_PUBLIC_KEY,
										Data: testKey[:],
									},
									{
										Type: unix.WGPEER_A_PRESHARED_KEY,
										Data: testKey[:],
									},
									{
										Type: unix.WGPEER_A_ENDPOINT,
										Data: (*(*[unix.SizeofSockaddrInet4]byte)(unsafe.Pointer(&unix.RawSockaddrInet4{
											Addr: [4]byte{192, 168, 1, 1},
											Port: sockaddrPort(1111),
										})))[:],
									},
									{
										Type: unix.WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL,
										Data: nlenc.Uint16Bytes(10),
									},
									{
										Type: unix.WGPEER_A_LAST_HANDSHAKE_TIME,
										Data: (*(*[sizeofTimespec64]byte)(unsafe.Pointer(&timespec64{
											Sec:  10,
											Nsec: 20,
										})))[:],
									},
									{
										Type: unix.WGPEER_A_RX_BYTES,
										Data: nlenc.Uint64Bytes(100),
									},
									{
										Type: unix.WGPEER_A_TX_BYTES,
										Data: nlenc.Uint64Bytes(200),
									},
									{
										Type: unix.WGPEER_A_ALLOWEDIPS,
										Data: mustAllowedIPs([]net.IPNet{
											wgtest.MustCIDR("192.168.1.10/32"),
											wgtest.MustCIDR("fd00::1/128"),
										}),
									},
									{
										Type: unix.WGPEER_A_PROTOCOL_VERSION,
										Data: nlenc.Uint32Bytes(1),
									},
								}...),
							},
							// "dummy" peer with only some necessary fields.
							{
								Type: 1,
								Data: m([]netlink.Attribute{
									{
										Type: unix.WGPEER_A_PUBLIC_KEY,
										Data: testKey[:],
									},
									{
										Type: unix.WGPEER_A_ENDPOINT,
										Data: (*(*[unix.SizeofSockaddrInet6]byte)(unsafe.Pointer(&unix.RawSockaddrInet6{
											Addr: [16]byte{
												0xfe, 0x80, 0x00, 0x00,
												0x00, 0x00, 0x00, 0x00,
												0x00, 0x00, 0x00, 0x00,
												0x00, 0x00, 0x00, 0x01,
											},
											Port: sockaddrPort(2222),
										})))[:],
									},
								}...),
							},
						}...),
					},
				}...),
			}}},
			devices: []*wgtypes.Device{
				{
					Name:         okName,
					Type:         wgtypes.LinuxKernel,
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
								wgtest.MustCIDR("192.168.1.10/32"),
								wgtest.MustCIDR("fd00::1/128"),
							},
							ProtocolVersion: 1,
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
					Data: m([]netlink.Attribute{
						{
							Type: unix.WGDEVICE_A_IFNAME,
							Data: nlenc.Bytes(okName),
						},
						{
							Type: unix.WGDEVICE_A_PRIVATE_KEY,
							Data: testKey[:],
						},
						{
							Type: unix.WGDEVICE_A_PEERS,
							Data: m(netlink.Attribute{
								Type: 0,
								Data: m([]netlink.Attribute{
									{
										Type: unix.WGPEER_A_PUBLIC_KEY,
										Data: keyA[:],
									},
									{
										Type: unix.WGPEER_A_ALLOWEDIPS,
										Data: mustAllowedIPs([]net.IPNet{
											wgtest.MustCIDR("192.168.1.10/32"),
											wgtest.MustCIDR("192.168.1.11/32"),
										}),
									},
								}...),
							}),
						},
					}...),
				},
				// Continuation of first peer list, new peer list.
				{
					Data: m(netlink.Attribute{
						Type: unix.WGDEVICE_A_PEERS,
						Data: m([]netlink.Attribute{
							{
								Type: 0,
								Data: m([]netlink.Attribute{
									{
										Type: unix.WGPEER_A_PUBLIC_KEY,
										Data: keyA[:],
									},
									{
										Type: unix.WGPEER_A_ALLOWEDIPS,
										Data: mustAllowedIPs([]net.IPNet{
											wgtest.MustCIDR("fd00:dead:beef:dead::/64"),
											wgtest.MustCIDR("fd00:dead:beef:ffff::/64"),
										}),
									},
								}...),
							},
							{
								Type: 1,
								Data: m([]netlink.Attribute{
									{
										Type: unix.WGPEER_A_PUBLIC_KEY,
										Data: keyB[:],
									},
									{
										Type: unix.WGPEER_A_ALLOWEDIPS,
										Data: mustAllowedIPs([]net.IPNet{
											wgtest.MustCIDR("10.10.10.0/24"),
											wgtest.MustCIDR("10.10.11.0/24"),
										}),
									},
								}...),
							},
						}...),
					}),
				},
				// Continuation of previous peer list, new peer list.
				{
					Data: m(netlink.Attribute{
						Type: unix.WGDEVICE_A_PEERS,
						Data: m([]netlink.Attribute{
							{
								Type: 0,
								Data: m([]netlink.Attribute{
									{
										Type: unix.WGPEER_A_PUBLIC_KEY,
										Data: keyB[:],
									},
									{
										Type: unix.WGPEER_A_ALLOWEDIPS,
										Data: mustAllowedIPs([]net.IPNet{
											wgtest.MustCIDR("10.10.12.0/24"),
											wgtest.MustCIDR("10.10.13.0/24"),
										}),
									},
								}...),
							},
							{
								Type: 1,
								Data: m([]netlink.Attribute{
									{
										Type: unix.WGPEER_A_PUBLIC_KEY,
										Data: keyC[:],
									},
									{
										Type: unix.WGPEER_A_ALLOWEDIPS,
										Data: mustAllowedIPs([]net.IPNet{
											wgtest.MustCIDR("fd00:1234::/32"),
											wgtest.MustCIDR("fd00:4567::/32"),
										}),
									},
								}...),
							},
						}...),
					}),
				},
			}},
			devices: []*wgtypes.Device{
				{
					Name:       okName,
					Type:       wgtypes.LinuxKernel,
					PrivateKey: testKey,
					Peers: []wgtypes.Peer{
						{
							PublicKey: keyA,
							AllowedIPs: []net.IPNet{
								wgtest.MustCIDR("192.168.1.10/32"),
								wgtest.MustCIDR("192.168.1.11/32"),
								wgtest.MustCIDR("fd00:dead:beef:dead::/64"),
								wgtest.MustCIDR("fd00:dead:beef:ffff::/64"),
							},
						},
						{
							PublicKey: keyB,
							AllowedIPs: []net.IPNet{
								wgtest.MustCIDR("10.10.10.0/24"),
								wgtest.MustCIDR("10.10.11.0/24"),
								wgtest.MustCIDR("10.10.12.0/24"),
								wgtest.MustCIDR("10.10.13.0/24"),
							},
						},
						{
							PublicKey: keyC,
							AllowedIPs: []net.IPNet{
								wgtest.MustCIDR("fd00:1234::/32"),
								wgtest.MustCIDR("fd00:4567::/32"),
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
				cmd   = unix.WG_CMD_GET_DEVICE
				flags = netlink.Request | netlink.Dump
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

func Test_parseTimespec(t *testing.T) {
	var zero [sizeofTimespec64]byte

	tests := []struct {
		name string
		b    []byte
		t    time.Time
		ok   bool
	}{
		{
			name: "bad",
			b:    []byte{0xff},
		},
		{
			name: "timespec32",
			b: (*(*[sizeofTimespec32]byte)(unsafe.Pointer(&timespec32{
				Sec:  1,
				Nsec: 2,
			})))[:],
			t:  time.Unix(1, 2),
			ok: true,
		},
		{
			name: "timespec64",
			b: (*(*[sizeofTimespec64]byte)(unsafe.Pointer(&timespec64{
				Sec:  2,
				Nsec: 1,
			})))[:],
			t:  time.Unix(2, 1),
			ok: true,
		},
		{
			name: "zero seconds",
			b: (*(*[sizeofTimespec64]byte)(unsafe.Pointer(&timespec64{
				Nsec: 1,
			})))[:],
			t:  time.Unix(0, 1),
			ok: true,
		},
		{
			name: "zero nanoseconds",
			b: (*(*[sizeofTimespec64]byte)(unsafe.Pointer(&timespec64{
				Sec: 1,
			})))[:],
			t:  time.Unix(1, 0),
			ok: true,
		},
		{
			name: "zero both",
			b:    zero[:],
			ok:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got time.Time
			err := parseTimespec(&got)(tt.b)
			if tt.ok && err != nil {
				t.Fatalf("failed to parse timespec: %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatal("expected an error, but none occurred")
			}
			if err != nil {
				t.Logf("err: %v", err)
				return
			}

			if diff := cmp.Diff(tt.t, got); diff != "" {
				t.Fatalf("unexpected time (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_timespec32MemoryLayout(t *testing.T) {
	// Assume unix.Timespec has 32-bit integers exclusively.
	if a := runtime.GOARCH; a != "386" {
		t.Skipf("skipping, architecture %q not handled in 32-bit only test", a)
	}

	// Verify unix.Timespec and timespec32 have an identical memory layout.
	uts := unix.Timespec{
		Sec:  1,
		Nsec: 2,
	}

	if diff := cmp.Diff(sizeofTimespec32, int(unsafe.Sizeof(unix.Timespec{}))); diff != "" {
		t.Fatalf("unexpected timespec size (-want +got):\n%s", diff)
	}

	ts := *(*timespec32)(unsafe.Pointer(&uts))

	if diff := cmp.Diff(uts.Sec, ts.Sec); diff != "" {
		t.Fatalf("unexpected timespec seconds (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(uts.Nsec, ts.Nsec); diff != "" {
		t.Fatalf("unexpected timespec nanoseconds (-want +got):\n%s", diff)
	}
}

func Test_timespec64MemoryLayout(t *testing.T) {
	// Assume unix.Timespec has 64-bit integers exclusively.
	if a := runtime.GOARCH; a != "amd64" {
		t.Skipf("skipping, architecture %q not handled in 64-bit only test", a)
	}

	// Verify unix.Timespec and timespec64 have an identical memory layout.
	uts := unix.Timespec{
		Sec:  1,
		Nsec: 2,
	}

	if diff := cmp.Diff(sizeofTimespec64, int(unsafe.Sizeof(unix.Timespec{}))); diff != "" {
		t.Fatalf("unexpected timespec size (-want +got):\n%s", diff)
	}

	ts := *(*timespec64)(unsafe.Pointer(&uts))

	if diff := cmp.Diff(uts.Sec, ts.Sec); diff != "" {
		t.Fatalf("unexpected timespec seconds (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(uts.Nsec, ts.Nsec); diff != "" {
		t.Fatalf("unexpected timespec nanoseconds (-want +got):\n%s", diff)
	}
}
