//+build openbsd

package wgopenbsd

import (
	"fmt"
	"testing"
	"unsafe"

	"github.com/google/go-cmp/cmp"
	"golang.zx2c4.com/wireguard/wgctrl/internal/wgopenbsd/internal/wgh"
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
			ptr := *(*uintptr)(unsafe.Pointer(&ifg.Ifgru[0]))

			if diff := cmp.Diff(uintptr(cbuf), ptr); diff != "" {
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
			// TODO(mdlayher): validate request, return device and peer information.
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
