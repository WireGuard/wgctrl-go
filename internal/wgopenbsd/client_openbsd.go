//+build openbsd

package wgopenbsd

import (
	"bytes"
	"fmt"
	"os"
	"runtime"
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
)

var _ wginternal.Client = &Client{}

// A Client provides access to OpenBSD WireGuard ioctl information.
type Client struct {
	fd int
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

	return &Client{
		fd: fd,
	}, true, nil
}

// Close implements wginternal.Client.
func (c *Client) Close() error {
	return unix.Close(c.fd)
}

// Devices implements wginternal.Client.
func (c *Client) Devices() ([]*wgtypes.Device, error) {
	ifg := wgh.Ifgroupreq{
		// Query for devices in the "wg" group.
		Name: [16]int8{0: 'w', 1: 'g'},
	}

	// Determine how many device names we must allocate memory for.
	if err := ioctl(c.fd, wgh.SIOCGIFGMEMB, unsafe.Pointer(&ifg)); err != nil {
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

	cbuf := C.malloc(C.sizeof_char * C.size_t(ifg.Len))
	defer C.free(cbuf)

	*(*uintptr)(unsafe.Pointer(&ifg.Ifgru[0])) = uintptr(cbuf)

	// Now actually fetch the device names.
	if err := ioctl(c.fd, wgh.SIOCGIFGMEMB, unsafe.Pointer(&ifg)); err != nil {
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
		// TODO(mdlayher): parsing for remaining peer fields.
		d.Peers = append(d.Peers, wgtypes.Peer{
			PublicKey: pk,
		})
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

		// Allocate enough space for n*30 (wgtypes.KeyLen) peer public keys and
		// point the kernel to our C memory.
		cbuf = C.reallocarray(cbuf, C.size_t(n), wgtypes.KeyLen)
		wgs.Peers = (*[wgtypes.KeyLen]uint8)(cbuf)

		// Query for a device by its name.
		if err := ioctl(c.fd, wgh.SIOCGWGSERV, unsafe.Pointer(&wgs)); err != nil {
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

// deviceName converts an interface name string to the format required to pass
// with wgh.WGGetServ.
func deviceName(name string) ([16]int8, error) {
	var out [unix.IFNAMSIZ]int8
	buf := []byte(name)
	if len(buf) > unix.IFNAMSIZ {
		return out, fmt.Errorf("wgopenbsd: interface name %q too long", name)
	}

	for i, b := range buf {
		out[i] = int8(b)
	}

	return out, nil
}

// ioctl is a raw wrapper for the ioctl system call.
func ioctl(fd int, req uint, arg unsafe.Pointer) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg))
	if errno != 0 {
		return os.NewSyscallError("ioctl", errno)
	}

	return nil
}
