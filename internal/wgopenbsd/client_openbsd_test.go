//+build openbsd

package wgopenbsd

import (
	"fmt"
	"os"
	"testing"
	"unsafe"

	"github.com/google/go-cmp/cmp"
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

	var calls int
	ifgrFunc := func(ifg *wgh.Ifgroupreq) error {
		// Verify the caller is asking for WireGuard interface group members.
		if diff := cmp.Diff(ifGroupWG, ifg.Name); diff != "" {
			t.Fatalf("unexpected interface group (-want +got):\n%s", diff)
		}

		switch calls {
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

		calls++
		return nil
	}

	c := &Client{
		ioctlIfgroupreq: ifgrFunc,
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
	const (
		device = "testwg0"

		nPeers      = 1
		nAllowedIPs = 2
	)

	var (
		priv = wgtest.MustPrivateKey()
		pub  = priv.PublicKey()
		peer = wgtest.MustPublicKey()
		psk  = wgtest.MustPresharedKey()
	)

	c := &Client{
		ioctlIfgroupreq: func(_ *wgh.Ifgroupreq) error {
			panic("no calls to Client.Devices, should not be called")
		},
	}

	d, err := c.Device(device)
	if err != nil {
		t.Fatalf("failed to get device: %v", err)
	}

	_, _, _ = pub, peer, psk

	want := &wgtypes.Device{
		Name:  device,
		Type:  wgtypes.OpenBSDKernel,
		Peers: []wgtypes.Peer{},
		/*

			TODO: enable when ready.

			PrivateKey: priv,
			PublicKey:  pub,
			ListenPort: 8080,
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
	tests := []struct {
		name string
		err  error
	}{
		/*

			TODO: enable when ready.

			{
				name: "ENXIO",
				err:  os.NewSyscallError("ioctl", unix.ENXIO),
			},
			{
				name: "ENOTTY",
				err:  os.NewSyscallError("ioctl", unix.ENOTTY),
			},
		*/
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{}

			if _, err := c.Device("wgnotexist0"); !os.IsNotExist(err) {
				t.Fatalf("expected is not exist, but got: %v", err)
			}
		})
	}
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
