//+build openbsd

package wgopenbsd

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/internal/wginternal"
	"golang.zx2c4.com/wireguard/wgctrl/internal/wgopenbsd/internal/wgh"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

/*
#cgo CFLAGS: -g -Wall
#include <stdlib.h>
*/
import "C"

const (
	sizeofIfgreq = uint32(unsafe.Sizeof(wgh.Ifgreq{}))
	sizeofWGIP   = unsafe.Sizeof(wgh.WGIP{})
)

var (
	// ifGroupWG is the WireGuard interface group name passed to the kernel.
	ifGroupWG = [16]byte{0: 'w', 1: 'g'}
)

var _ wginternal.Client = &Client{}

// A Client provides access to OpenBSD WireGuard ioctl information.
type Client struct {
	// Hooks which use system calls by default, but can also be swapped out
	// during tests.
	close           func() error
	ioctlIfgroupreq func(ifg *wgh.Ifgroupreq, cbuf unsafe.Pointer) error
	ioctlWGGetServ  func(wgs *wgh.WGGetServ, cbuf unsafe.Pointer) error
	ioctlWGGetPeer  func(wgp *wgh.WGGetPeer, cbuf unsafe.Pointer) error
}

// New creates a new Client and returns whether or not the ioctl interface
// is available.
func New() (*Client, bool, error) {
	// The OpenBSD ioctl interface operates on a generic AF_INET socket.
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return nil, false, err
	}

	// TODO(mdlayher): find a call to invoke here to probe for availability.
	// c.Devices won't work because it returns a "not found" error when the
	// kernel WireGuard implementation is available but the interface group
	// has no members.

	// By default, use system call implementations for all hook functions.
	return &Client{
		close:           func() error { return unix.Close(fd) },
		ioctlIfgroupreq: ioctlIfgroupreq(fd),
		ioctlWGGetServ:  ioctlWGGetServ(fd),
		ioctlWGGetPeer:  ioctlWGGetPeer(fd),
	}, true, nil
}

// Close implements wginternal.Client.
func (c *Client) Close() error {
	return c.close()
}

// Devices implements wginternal.Client.
func (c *Client) Devices() ([]*wgtypes.Device, error) {
	ifg := wgh.Ifgroupreq{
		// Query for devices in the "wg" group.
		Name: ifGroupWG,
	}

	// Determine how many device names we must allocate memory for.
	if err := c.ioctlIfgroupreq(&ifg, nil); err != nil {
		return nil, err
	}

	// ifg.Len is size in bytes; allocate enough C memory for the correct number
	// of wgh.Ifreq and then store a pointer to the C memory address where the
	// data should be written in the ifg.Ifgru union.
	//
	// C memory is allocated to store "[l]wgh.Ifreq" data in order to ensure
	// that the Go compiler does not move a slice and thus invalidate the memory
	// address passed to the following ioctl call.
	//
	// See the conversation beginning here in #darkarts on Gophers Slack:
	// https://gophers.slack.com/archives/C1C1YSQBT/p1557956939402700.
	l := ifg.Len / sizeofIfgreq

	cbuf := C.malloc(C.size_t(ifg.Len))
	defer C.free(cbuf)

	*(*uintptr)(unsafe.Pointer(&ifg.Ifgru[0])) = uintptr(cbuf)

	// Now actually fetch the device names.
	if err := c.ioctlIfgroupreq(&ifg, cbuf); err != nil {
		return nil, err
	}

	// Keep this alive until we're done doing the ioctl dance.
	runtime.KeepAlive(&ifg)

	// Perform the actual conversion to []wgh.Ifreq. See:
	// https://github.com/golang/go/wiki/cgo#turning-c-arrays-into-go-slices.
	ifgrs := (*[1 << 30]wgh.Ifgreq)(cbuf)[:l:l]

	devices := make([]*wgtypes.Device, 0, l)
	for _, ifgr := range ifgrs {
		// Remove any trailing NULL bytes from the interface names.
		d, err := c.Device(string(bytes.TrimRight(ifgr.Ifgrqu[:], "\x00")))
		if err != nil {
			return nil, err
		}

		devices = append(devices, d)
	}

	return devices, nil
}

// Device implements wginternal.Client.
func (c *Client) Device(name string) (*wgtypes.Device, error) {
	d, pkeys, err := c.getServ(name)
	if err != nil {
		return nil, err
	}

	d.Peers = make([]wgtypes.Peer, 0, len(pkeys))
	for _, pk := range pkeys {
		p, err := c.getPeer(d.Name, pk)
		if err != nil {
			return nil, err
		}

		d.Peers = append(d.Peers, *p)
	}

	return d, nil
}

// ConfigureDevice implements wginternal.Client.
func (c *Client) ConfigureDevice(name string, cfg wgtypes.Config) error {
	// Unimplemented: "not exist" error means this code can be built but is
	// effectively a no-op.
	return os.ErrNotExist
}

// getServ fetches a device and the public keys of its peers using an ioctl.
func (c *Client) getServ(name string) (*wgtypes.Device, []wgtypes.Key, error) {
	nb, err := deviceName(name)
	if err != nil {
		return nil, nil, err
	}

	// Fetch information for the specified device, and indicate that we have
	// pre-allocated room for peer public keys. 8 is the initial array size
	// value used by ncon's wg fork.
	wgs := wgh.WGGetServ{
		Name:      nb,
		Num_peers: 8,
	}

	var (
		// The amount of space we should allocate for peer public keys, and a
		// pointer to the C memory itself. Any return site _must_ free cbuf;
		// we aren't using defer because of the loop and the use of reallocarray
		// means the location cbuf points to can change.
		n    uint64
		cbuf unsafe.Pointer
	)

	for {
		// Updated on each loop iteration to provide enough space in case the
		// kernel tells us we need to provide more space.
		n = wgs.Num_peers

		// Allocate enough space for n*30 (wgtypes.KeyLen) peer public key bytes
		// and point the kernel to our C memory.
		cbuf = C.reallocarray(cbuf, C.size_t(n), wgtypes.KeyLen)
		wgs.Peers = (*[wgtypes.KeyLen]byte)(cbuf)

		// Query for a device by its name.
		if err := c.ioctlWGGetServ(&wgs, cbuf); err != nil {
			C.free(cbuf)
			return nil, nil, err
		}

		// Did the kernel tell us there are more peers than can fit in our
		// current memory? If not, we're done.
		if wgs.Num_peers <= n {
			// Update n one final time so we know how much memory we need to
			// copy from C to Go.
			n = wgs.Num_peers
			break
		}
	}

	// Convert C memory (*[32]byte) directly to []wgtypes.Key (32 bytes each)
	// and copy into a new Go slice so no C data is retained beyond this
	// function. See also:
	// https://github.com/golang/go/wiki/cgo#turning-c-arrays-into-go-slices.
	keys := make([]wgtypes.Key, n)
	copy(keys, (*[1 << 30]wgtypes.Key)(cbuf)[:n:n])
	C.free(cbuf)

	return &wgtypes.Device{
		Name:       name,
		Type:       wgtypes.OpenBSDKernel,
		PublicKey:  wgs.Pubkey,
		ListenPort: int(wgs.Port),
	}, keys, nil
}

// getPeer fetches a peer associated with a device and a public key.
func (c *Client) getPeer(device string, pubkey wgtypes.Key) (*wgtypes.Peer, error) {
	nb, err := deviceName(device)
	if err != nil {
		return nil, err
	}

	// The algorithm implemented here is the same as the one documented in
	// getServ, but we are fetching WGIP allowed IP arrays instead of peer
	// public keys. See the more in-depth documentation there.

	// 16 is the initial array size value used by ncon's wg fork.
	wgp := wgh.WGGetPeer{
		Name:    nb,
		Pubkey:  pubkey,
		Num_aip: 16,
	}

	var (
		// Any return site _must_ free cbuf; we aren't using defer immediately
		// because of the loop and the use of reallocarray means the location
		// cbuf points to can change.
		n    uint64
		cbuf unsafe.Pointer
	)

	for {
		n = wgp.Num_aip

		// Allocate enough space for n WGIP structures in an array.
		cbuf = C.reallocarray(cbuf, C.size_t(n), C.size_t(sizeofWGIP))
		wgp.Aip = (*[sizeofWGIP]byte)(cbuf)

		// Query for a peer by its associated device and public key.
		if err := c.ioctlWGGetPeer(&wgp, cbuf); err != nil {
			C.free(cbuf)
			return nil, err
		}

		// Did the kernel tell us there are more allowed IPs than can fit in our
		// current memory? If not, we're done.
		if wgp.Num_aip <= n {
			// Update n one final time so we know how much memory we need to
			// copy from C to Go.
			n = wgp.Num_aip
			break
		}
	}

	// No more loop and no more chance for cbuf address to change, so defer
	// freeing for any further return sites.
	defer C.free(cbuf)

	endpoint, err := parseEndpoint(wgp.Ip)
	if err != nil {
		return nil, err
	}

	// Copy C memory into a Go slice, see also:
	// https://github.com/golang/go/wiki/cgo#turning-c-arrays-into-go-slices.
	allowedIPs, err := parseAllowedIPs((*[1 << 30]wgh.WGIP)(cbuf)[:n:n])
	if err != nil {
		return nil, err
	}

	return &wgtypes.Peer{
		PublicKey:         pubkey,
		PresharedKey:      wgp.Psk,
		Endpoint:          endpoint,
		LastHandshakeTime: time.Unix(wgp.Last_handshake.Sec, wgp.Last_handshake.Nsec),
		ReceiveBytes:      int64(wgp.Rx_bytes),
		TransmitBytes:     int64(wgp.Tx_bytes),
		AllowedIPs:        allowedIPs,
	}, nil
}

// deviceName converts an interface name string to the format required to pass
// with wgh.WGGetServ.
func deviceName(name string) ([16]byte, error) {
	var out [unix.IFNAMSIZ]byte
	if len(name) > unix.IFNAMSIZ {
		return out, fmt.Errorf("wgopenbsd: interface name %q too long", name)
	}

	copy(out[:], name)
	return out, nil
}

// parseEndpoint parses a peer endpoint from a wgh.WGIP structure.
func parseEndpoint(ip wgh.WGIP) (*net.UDPAddr, error) {
	// sockaddr* structures have family at index 1.
	switch ip[1] {
	case unix.AF_INET:
		sa := *(*unix.RawSockaddrInet4)(unsafe.Pointer(&ip[0]))

		ep := &net.UDPAddr{
			IP:   make(net.IP, net.IPv4len),
			Port: int(sa.Port),
		}
		copy(ep.IP, sa.Addr[:])

		return ep, nil
	case unix.AF_INET6:
		sa := *(*unix.RawSockaddrInet6)(unsafe.Pointer(&ip[0]))

		// TODO(mdlayher): IPv6 zone?
		ep := &net.UDPAddr{
			IP:   make(net.IP, net.IPv6len),
			Port: int(sa.Port),
		}
		copy(ep.IP, sa.Addr[:])

		return ep, nil
	default:
		// No endpoint configured.
		return nil, nil
	}
}

// parseAllowedIPs parses allowed IPs from a []wgh.WGIP slice.
func parseAllowedIPs(aips []wgh.WGIP) ([]net.IPNet, error) {
	ipns := make([]net.IPNet, 0, len(aips))
	for _, aip := range aips {
		var ipn net.IPNet

		// sockaddr* structures have family at index 1.
		switch aip[1] {
		case unix.AF_INET:
			ip := *(*unix.RawSockaddrInet4)(unsafe.Pointer(&aip[0]))

			ipn.IP = make(net.IP, net.IPv4len)
			copy(ipn.IP, ip.Addr[:])
			ipn.Mask = net.CIDRMask(int(ip.Port), 32)
		case unix.AF_INET6:
			ip := *(*unix.RawSockaddrInet6)(unsafe.Pointer(&aip[0]))

			ipn.IP = make(net.IP, net.IPv6len)
			copy(ipn.IP, ip.Addr[:])
			ipn.Mask = net.CIDRMask(int(ip.Port), 128)
		default:
			// Unrecognized address family?
			continue
		}

		ipns = append(ipns, ipn)
	}

	return ipns, nil
}

// ioctlIfgroupreq returns a function which performs the appropriate ioctl on
// fd to retrieve members of an interface group.
func ioctlIfgroupreq(fd int) func(*wgh.Ifgroupreq, unsafe.Pointer) error {
	// ioctl doesn't need a direct pointer to the C memory.
	return func(ifg *wgh.Ifgroupreq, _ unsafe.Pointer) error {
		return ioctl(fd, wgh.SIOCGIFGMEMB, unsafe.Pointer(ifg))
	}
}

// ioctlWGGetServ returns a function which performs the appropriate ioctl on
// fd to fetch information about a WireGuard device.
func ioctlWGGetServ(fd int) func(*wgh.WGGetServ, unsafe.Pointer) error {
	// ioctl doesn't need a direct pointer to the C memory.
	return func(wgs *wgh.WGGetServ, _ unsafe.Pointer) error {
		return ioctl(fd, wgh.SIOCGWGSERV, unsafe.Pointer(wgs))
	}
}

// ioctlWGGetPeer returns a function which performs the appropriate ioctl on
// fd to fetch information about a peer associated with a WireGuard device.
func ioctlWGGetPeer(fd int) func(*wgh.WGGetPeer, unsafe.Pointer) error {
	// ioctl doesn't need a direct pointer to the C memory.
	return func(wgp *wgh.WGGetPeer, _ unsafe.Pointer) error {
		return ioctl(fd, wgh.SIOCGWGPEER, unsafe.Pointer(wgp))
	}
}

// ioctl is a raw wrapper for the ioctl system call.
func ioctl(fd int, req uint, arg unsafe.Pointer) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg))
	if errno != 0 {
		return os.NewSyscallError("ioctl", errno)
	}

	return nil
}
