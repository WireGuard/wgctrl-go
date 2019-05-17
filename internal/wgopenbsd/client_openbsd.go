//+build openbsd

package wgopenbsd

import (
	"bytes"
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
		devices = append(devices, &wgtypes.Device{
			// Remove any trailing NULL bytes from the interface names.
			Name: string(bytes.TrimRight(ifgr.Ifgrqu[:], "\x00")),
			Type: wgtypes.OpenBSDKernel,
		})
	}

	return devices, nil
}

// Device implements wginternal.Client.
func (c *Client) Device(name string) (*wgtypes.Device, error) {
	// Unimplemented: "not exist" error means this code can be built but is
	// effectively a no-op.
	return nil, os.ErrNotExist
}

// ConfigureDevice implements wginternal.Client.
func (c *Client) ConfigureDevice(name string, cfg wgtypes.Config) error {
	// Unimplemented: "not exist" error means this code can be built but is
	// effectively a no-op.
	return os.ErrNotExist
}

// ioctl is a raw wrapper for the ioctl system call.
func ioctl(fd int, req uint, arg unsafe.Pointer) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg))
	if errno != 0 {
		return os.NewSyscallError("ioctl", errno)
	}

	return nil
}
