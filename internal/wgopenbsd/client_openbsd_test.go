//+build openbsd

package wgopenbsd

import (
	"net"
	"os"
	"testing"
	"time"
	"unsafe"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/internal/wgopenbsd/internal/wgh"
	"golang.zx2c4.com/wireguard/wgctrl/internal/wgtest"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestClientDevices(t *testing.T) {
	// Fixed parameters for the test.
	const (
		n = 2

		devA = "testwg0"
		devB = "testwg1"
	)

	var ifgrCalls int
	ifgrFunc := func(ifg *wgh.Ifgroupreq) error {
		// Verify the caller is asking for WireGuard interface group members.
		if diff := cmp.Diff(ifGroupWG, ifg.Name); diff != "" {
			t.Fatalf("unexpected interface group (-want +got):\n%s", diff)
		}

		switch ifgrCalls {
		case 0:
			// Inform the caller that we have n device names available.
			ifg.Len = n * wgh.SizeofIfgreq
		case 1:
			// The structure pointed at is the first in an array. Populate the
			// array memory with device names.
			*(*[n]wgh.Ifgreq)(unsafe.Pointer(ifg.Groups)) = [n]wgh.Ifgreq{
				{Ifgrqu: devName(devA)},
				{Ifgrqu: devName(devB)},
			}
		default:
			t.Fatal("too many calls to ioctlIfgroupreq")
		}

		ifgrCalls++
		return nil
	}

	// TODO(mdlayher): add a test case where the data.Size field changes between
	// call 1 and 2, so the caller must loop again to determine how much memory
	// to allocate for the memory slice.

	var wgIOCalls int
	wgDataIOFunc := func(data *wgh.WGDataIO) error {
		// Expect two calls per device, where the first call indicates the
		// number of bytes to populate, and the second would normally populate
		// the caller's memory.
		switch wgIOCalls {
		case 0, 2:
			data.Size = wgh.SizeofWGInterfaceIO
		case 1, 3:
			// No-op, nothing to fill out.
		default:
			t.Fatal("too many calls to ioctlWGDataIO")
		}

		wgIOCalls++
		return nil
	}

	c := &Client{
		ioctlIfgroupreq: ifgrFunc,
		ioctlWGDataIO:   wgDataIOFunc,
	}

	devices, err := c.Devices()
	if err != nil {
		t.Fatalf("failed to get devices: %v", err)
	}

	// This test does basic sanity checking for fetching many devices. Other
	// tests will handle more complex cases.
	want := []*wgtypes.Device{
		{
			Name:  devA,
			Type:  wgtypes.OpenBSDKernel,
			Peers: []wgtypes.Peer{},
		},
		{
			Name:  devB,
			Type:  wgtypes.OpenBSDKernel,
			Peers: []wgtypes.Peer{},
		},
	}

	if diff := cmp.Diff(want, devices); diff != "" {
		t.Fatalf("unexpected devices (-want +got):\n%s", diff)
	}
}

func TestClientDeviceBasic(t *testing.T) {
	// Fixed parameters for the test.
	const device = "testwg0"

	var (
		priv  = wgtest.MustPrivateKey()
		pub   = priv.PublicKey()
		peerA = wgtest.MustPublicKey()
		peerB = wgtest.MustPublicKey()
		peerC = wgtest.MustPublicKey()
		psk   = wgtest.MustPresharedKey()
	)

	var calls int
	c := &Client{
		ioctlIfgroupreq: func(_ *wgh.Ifgroupreq) error {
			panic("no calls to Client.Devices, should not be called")
		},
		ioctlWGDataIO: func(data *wgh.WGDataIO) error {
			// Verify the caller is asking for WireGuard interface group members.
			if diff := cmp.Diff(devName(device), data.Name); diff != "" {
				t.Fatalf("unexpected interface name (-want +got):\n%s", diff)
			}

			switch calls {
			case 0:
				// Inform the caller that we have one device, one peer, and
				// two allowed IPs associated with that peer.
				data.Size = wgh.SizeofWGInterfaceIO +
					wgh.SizeofWGPeerIO + 2*wgh.SizeofWGAIPIO +
					wgh.SizeofWGPeerIO + wgh.SizeofWGAIPIO +
					wgh.SizeofWGPeerIO
			case 1:
				// The caller expects a WGInterfaceIO which is populated with
				// data, so fill it out now.
				b := pack(
					&wgh.WGInterfaceIO{
						Flags: wgh.WG_INTERFACE_HAS_PUBLIC |
							wgh.WG_INTERFACE_HAS_PRIVATE |
							wgh.WG_INTERFACE_HAS_PORT |
							wgh.WG_INTERFACE_HAS_RTABLE,
						Port:        8080,
						Rtable:      1,
						Public:      pub,
						Private:     priv,
						Peers_count: 3,
					},
					&wgh.WGPeerIO{
						Flags: wgh.WG_PEER_HAS_PUBLIC |
							wgh.WG_PEER_HAS_PSK |
							wgh.WG_PEER_HAS_PKA |
							wgh.WG_PEER_HAS_ENDPOINT,
						Protocol_version: 1,
						Public:           peerA,
						Psk:              psk,
						Pka:              60,
						Endpoint: *(*[28]byte)(unsafe.Pointer(&unix.RawSockaddrInet4{
							Len:    uint8(unsafe.Sizeof(unix.RawSockaddrInet4{})),
							Family: unix.AF_INET,
							Port:   uint16(bePort(1024)),
							Addr:   [4]byte{192, 0, 2, 0},
						})),
						Txbytes: 1,
						Rxbytes: 2,
						Last_handshake: wgh.Timespec{
							Sec:  1,
							Nsec: 2,
						},
						Aips_count: 2,
					},
					&wgh.WGAIPIO{
						Af:   unix.AF_INET,
						Cidr: 24,
						Addr: [16]byte{0: 192, 1: 168, 2: 1, 3: 0},
					},
					&wgh.WGAIPIO{
						Af:   unix.AF_INET6,
						Cidr: 64,
						Addr: [16]byte{0: 0xfd},
					},
					&wgh.WGPeerIO{
						Flags: wgh.WG_PEER_HAS_PUBLIC |
							wgh.WG_PEER_HAS_ENDPOINT,
						Public: peerB,
						Endpoint: *(*[28]byte)(unsafe.Pointer(&unix.RawSockaddrInet6{
							Len:    uint8(unsafe.Sizeof(unix.RawSockaddrInet6{})),
							Family: unix.AF_INET6,
							Port:   uint16(bePort(2048)),
							Addr:   [16]byte{15: 0x01},
						})),
						Aips_count: 1,
					},
					&wgh.WGAIPIO{
						Af:   unix.AF_INET6,
						Cidr: 128,
						Addr: [16]byte{0: 0x20, 1: 0x01, 2: 0x0d, 3: 0xb8, 15: 0x01},
					},
					&wgh.WGPeerIO{
						Flags:  wgh.WG_PEER_HAS_PUBLIC,
						Public: peerC,
					},
				)

				data.Interface = (*wgh.WGInterfaceIO)(unsafe.Pointer(&b[0]))
			default:
				t.Fatal("too many calls to ioctlWGDataIO")
			}

			calls++
			return nil
		},
	}

	d, err := c.Device(device)
	if err != nil {
		t.Fatalf("failed to get device: %v", err)
	}

	want := &wgtypes.Device{
		Name:         device,
		Type:         wgtypes.OpenBSDKernel,
		PrivateKey:   priv,
		PublicKey:    pub,
		ListenPort:   8080,
		FirewallMark: 1,
		Peers: []wgtypes.Peer{
			{
				PublicKey:                   peerA,
				PresharedKey:                psk,
				Endpoint:                    wgtest.MustUDPAddr("192.0.2.0:1024"),
				PersistentKeepaliveInterval: 60 * time.Second,
				ReceiveBytes:                2,
				TransmitBytes:               1,
				LastHandshakeTime:           time.Unix(1, 2),
				AllowedIPs: []net.IPNet{
					wgtest.MustCIDR("192.168.1.0/24"),
					wgtest.MustCIDR("fd00::/64"),
				},
				ProtocolVersion: 1,
			},
			{
				PublicKey:  peerB,
				Endpoint:   wgtest.MustUDPAddr("[::1]:2048"),
				AllowedIPs: []net.IPNet{wgtest.MustCIDR("2001:db8::1/128")},
			},
			{
				PublicKey:  peerC,
				AllowedIPs: []net.IPNet{},
			},
		},
	}

	if diff := cmp.Diff(want, d); diff != "" {
		t.Fatalf("unexpected device (-want +got):\n%s", diff)
	}
}

func TestClientDeviceNotExist(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{
			name: "ENXIO",
			err:  os.NewSyscallError("ioctl", unix.ENXIO),
		},
		{
			name: "ENOTTY",
			err:  os.NewSyscallError("ioctl", unix.ENOTTY),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				ioctlWGDataIO: func(_ *wgh.WGDataIO) error {
					return tt.err
				},
			}

			if _, err := c.Device("wgnotexist0"); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("expected is not exist, but got: %v", err)
			}
		})
	}
}

func TestClientDeviceWrongMemorySize(t *testing.T) {
	c := &Client{
		ioctlWGDataIO: func(data *wgh.WGDataIO) error {
			// Pass a nonsensical number of bytes back to the caller.
			data.Size = 1
			return nil
		},
	}

	_, err := c.Device("wg0")
	if err == nil {
		t.Fatal("expected an error, but none occurred")
	}

	t.Logf("err: %v", err)
}

// pack packs a WGInterfaceIO and trailing WGPeerIO/WGAIPIO values in a
// contiguous byte slice to emulate the kernel module output.
func pack(ifio *wgh.WGInterfaceIO, values ...interface{}) []byte {
	out := (*(*[wgh.SizeofWGInterfaceIO]byte)(unsafe.Pointer(ifio)))[:]

	for _, v := range values {
		switch v := v.(type) {
		case *wgh.WGPeerIO:
			b := (*(*[wgh.SizeofWGPeerIO]byte)(unsafe.Pointer(v)))[:]
			out = append(out, b...)
		case *wgh.WGAIPIO:
			b := (*(*[wgh.SizeofWGAIPIO]byte)(unsafe.Pointer(v)))[:]
			out = append(out, b...)
		default:
			panicf("pack: invalid type %T", v)
		}
	}

	return out
}

func devName(name string) [16]byte {
	nb, err := deviceName(name)
	if err != nil {
		panicf("failed to make device name bytes: %v", err)
	}

	return nb
}
