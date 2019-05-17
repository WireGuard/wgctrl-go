//+build openbsd

package wgopenbsd

import (
	"fmt"
	"net"
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

	var calls int
	ifgrFunc := func(ifg *wgh.Ifgroupreq, cbuf unsafe.Pointer) error {
		// Verify the caller is asking for WireGuard interface group members.
		if diff := cmp.Diff(ifGroupWG, ifg.Name); diff != "" {
			t.Fatalf("unexpected interface group (-want +got):\n%s", diff)
		}

		switch calls {
		case 0:
			// Inform the caller that we have n device names available.
			ifg.Len = n * sizeofIfgreq
		case 1:
			// Verify that the pointer stored in the union matches the pointer
			// to C memory received by this function.
			if diff := cmp.Diff(uintptr(cbuf), *(*uintptr)(unsafe.Pointer(&ifg.Ifgru[0]))); diff != "" {
				t.Fatalf("unexpected pointer to C memory (-want +got):\n%s", diff)
			}

			// Populate the C memory with device names.
			*(*[n]wgh.Ifgreq)(cbuf) = [n]wgh.Ifgreq{
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
		ioctlWGGetServ: func(wgs *wgh.WGGetServ, _ unsafe.Pointer) error {
			// No added device information, no peer information.
			wgs.Num_peers = 0
			return nil
		},
		ioctlWGGetPeer: func(_ *wgh.WGGetPeer, _ unsafe.Pointer) error {
			panic("no peers configured, should not be called")
		},
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

	// TODO(mdlayher): return device private key when the interface supports it.
	var (
		pub  = wgtest.MustPublicKey()
		peer = wgtest.MustPublicKey()
		psk  = wgtest.MustPresharedKey()
	)

	//var calls int

	c := &Client{
		ioctlIfgroupreq: func(_ *wgh.Ifgroupreq, _ unsafe.Pointer) error {
			panic("no calls to Client.Devices, should not be called")
		},
		ioctlWGGetServ: func(wgs *wgh.WGGetServ, cbuf unsafe.Pointer) error {
			// Verify that the pointer stored in wgs matches the pointer
			// to C memory received by this function.
			if diff := cmp.Diff(cbuf, unsafe.Pointer(&wgs.Peers[0])); diff != "" {
				t.Fatalf("unexpected pointer to C memory (-want +got):\n%s", diff)
			}

			// Populate the C memory with peer public key.
			*(*[nPeers]wgtypes.Key)(cbuf) = [nPeers]wgtypes.Key{peer}

			// Fill in some device information and indicate number of peers.
			wgs.Pubkey = pub
			wgs.Port = 8080
			wgs.Num_peers = nPeers
			return nil
		},
		ioctlWGGetPeer: func(wgp *wgh.WGGetPeer, cbuf unsafe.Pointer) error {
			// Verify the device name and peer public key.
			if diff := cmp.Diff(devName(device), wgp.Name); diff != "" {
				t.Fatalf("unexpected device name bytes (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(peer, wgtypes.Key(wgp.Pubkey)); diff != "" {
				t.Fatalf("unexpected peer public key (-want +got):\n%s", diff)
			}

			// Verify that the pointer stored in wgp matches the pointer
			// to C memory received by this function.
			if diff := cmp.Diff(cbuf, unsafe.Pointer(&wgp.Aip[0])); diff != "" {
				t.Fatalf("unexpected pointer to C memory (-want +got):\n%s", diff)
			}

			// Populate the C memory with allowed IPs.
			wgp.Num_aip = nAllowedIPs
			*(*[nAllowedIPs]wgh.WGIP)(cbuf) = [nAllowedIPs]wgh.WGIP{
				// unix.RawSockaddrInet* structures are repurposed for allowed
				// IP subnets. Port is treated as the CIDR mask.
				*(*wgh.WGIP)(unsafe.Pointer(&unix.RawSockaddrInet4{
					Family: unix.AF_INET,
					Addr:   [4]byte{192, 168, 1, 0},
					Port:   24,
				})),
				*(*wgh.WGIP)(unsafe.Pointer(&unix.RawSockaddrInet6{
					Family: unix.AF_INET6,
					Addr:   [16]byte{0: 0xfd},
					Port:   64,
				})),
			}

			// Fill in peer information.
			wgp.Psk = psk
			wgp.Tx_bytes = 1
			wgp.Rx_bytes = 2
			wgp.Ip = *(*wgh.WGIP)(unsafe.Pointer(&unix.RawSockaddrInet6{
				Family: unix.AF_INET6,
				Addr:   [16]byte{0: 0xfd, 15: 0x01},
				// Workaround for native vs big endianness.
				Port: uint16(bePort(1024)),
			}))
			wgp.Last_handshake = wgh.Timespec{
				Sec:  1,
				Nsec: 2,
			}
			return nil
		},
	}

	d, err := c.Device(device)
	if err != nil {
		t.Fatalf("failed to get device: %v", err)
	}

	want := &wgtypes.Device{
		Name:       device,
		Type:       wgtypes.OpenBSDKernel,
		PublicKey:  pub,
		ListenPort: 8080,
		Peers: []wgtypes.Peer{{
			PublicKey:         peer,
			PresharedKey:      psk,
			Endpoint:          wgtest.MustUDPAddr("[fd00::1]:1024"),
			ReceiveBytes:      2,
			TransmitBytes:     1,
			LastHandshakeTime: time.Unix(1, 2),
			AllowedIPs: []net.IPNet{
				wgtest.MustCIDR("192.168.1.0/24"),
				wgtest.MustCIDR("fd00::/64"),
			},
		}},
	}

	if diff := cmp.Diff(want, d); diff != "" {
		t.Fatalf("unexpected device (-want +got):\n%s", diff)
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
