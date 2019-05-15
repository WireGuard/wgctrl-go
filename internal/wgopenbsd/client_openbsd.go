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

	// Check to see if the ioctl interface is available.
	c := &Client{fd: fd}
	if _, err := c.Devices(); err != nil {
		_ = c.Close()

		if os.IsNotExist(err) {
			// The ioctl interface is not available.
			return nil, false, nil
		}

		return nil, false, err
	}

	return c, true, nil
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

	// ifg.Len is in bytes; allocate enough space for the correct number
	// of devices and then store a pointer to the address where the data should
	// be written in the ifg.Ifgru union.
	//
	// TODO(mdlayher): is this actually safe? Can we guarantee that the memory
	// address we pass to the kernel remains valid for when we need to read
	// from the slice below?
	ifgrs := make([]wgh.Ifgreq, ifg.Len/sizeofIfgreq)
	*(*uintptr)(unsafe.Pointer(&ifg.Ifgru[0])) = uintptr(unsafe.Pointer(&ifgrs[0]))

	// Now actually fetch the device names.
	if err := ioctl(c.fd, wgh.SIOCGIFGMEMB, unsafe.Pointer(&ifg)); err != nil {
		return nil, err
	}

	// Keep this alive until we're done doing the ioctl dance.
	runtime.KeepAlive(&ifg)

	devices := make([]*wgtypes.Device, 0, len(ifgrs))
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
