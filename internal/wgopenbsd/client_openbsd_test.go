//+build openbsd

package wgopenbsd

import (
	"encoding/binary"
	"fmt"
	"os"
	"testing"
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
		priv = wgtest.MustPrivateKey()
		pub  = priv.PublicKey()
		peer = wgtest.MustPublicKey()
		psk  = wgtest.MustPresharedKey()
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
				// Inform the caller that we have a WGInterfaceIO available.
				data.Size = wgh.SizeofWGInterfaceIO
			case 1:
				// The caller expects a WGInterfaceIO which is populated with
				// data, so fill it out now.
				var nb [2]byte
				binary.BigEndian.PutUint16(nb[:], 8080)

				*(*wgh.WGInterfaceIO)(unsafe.Pointer(data.Mem)) = wgh.WGInterfaceIO{
					Flags: wgh.WG_INTERFACE_HAS_PUBLIC |
						wgh.WG_INTERFACE_HAS_PRIVATE |
						wgh.WG_INTERFACE_HAS_PORT |
						wgh.WG_INTERFACE_HAS_RTABLE,
					Port:    *(*uint16)(unsafe.Pointer(&nb[0])),
					Private: priv,
					Public:  pub,
					Rtable:  1,
				}
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

	_, _ = peer, psk

	want := &wgtypes.Device{
		Name:         device,
		Type:         wgtypes.OpenBSDKernel,
		PrivateKey:   priv,
		PublicKey:    pub,
		ListenPort:   8080,
		FirewallMark: 1,
		Peers:        []wgtypes.Peer{},
		/*
			TODO: enable when ready.

			Peers: []wgtypes.Peer{{
				PublicKey:                   peer,
				PresharedKey:                psk,
				Endpoint:                    wgtest.MustUDPAddr("[fd00::1]:1024"),
				PersistentKeepaliveInterval: 60 * time.Second,
				ReceiveBytes:                2,
				TransmitBytes:               1,
				LastHandshakeTime:           time.Unix(1, 2),
				AllowedIPs: []net.IPNet{
					wgtest.MustCIDR("192.168.1.0/24"),
					wgtest.MustCIDR("fd00::/64"),
				},
			}},
		*/
	}

	if diff := cmp.Diff(want, d); diff != "" {
		t.Fatalf("unexpected device (-want +got):\n%s", diff)
	}
}

func TestClientDeviceNotExist(t *testing.T) {
	c := &Client{
		ioctlWGDataIO: func(_ *wgh.WGDataIO) error {
			return os.NewSyscallError("ioctl", unix.ENXIO)
		},
	}

	if _, err := c.Device("wgnotexist0"); !os.IsNotExist(err) {
		t.Fatalf("expected is not exist, but got: %v", err)
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

func devName(name string) [16]byte {
	nb, err := deviceName(name)
	if err != nil {
		panicf("failed to make device name bytes: %v", err)
	}

	return nb
}

func panicf(format string, a ...interface{}) {
	panic(fmt.Sprintf(format, a...))
}
