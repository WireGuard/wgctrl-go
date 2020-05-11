//+build openbsd

package wgopenbsd

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/internal/wginternal"
	"golang.zx2c4.com/wireguard/wgctrl/internal/wgopenbsd/internal/wgh"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
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
	ioctlIfgroupreq func(ifg *wgh.Ifgroupreq) error
	ioctlWGDataIO   func(data *wgh.WGDataIO) error
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
		ioctlWGDataIO:   ioctlWGDataIO(fd),
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
	if err := c.ioctlIfgroupreq(&ifg); err != nil {
		return nil, err
	}

	// ifg.Len is size in bytes; allocate enough memory for the correct number
	// of wgh.Ifgreq and then store a pointer to the memory where the data
	// should be written (ifgrs) in ifg.Groups.
	//
	// From a thread in golang-nuts, this pattern is valid:
	// "It would be OK to pass a pointer to a struct to ioctl if the struct
	// contains a pointer to other Go memory, but the struct field must have
	// pointer type."
	// See: https://groups.google.com/forum/#!topic/golang-nuts/FfasFTZvU_o.
	ifgrs := make([]wgh.Ifgreq, ifg.Len/wgh.SizeofIfgreq)
	ifg.Groups = &ifgrs[0]

	// Now actually fetch the device names.
	if err := c.ioctlIfgroupreq(&ifg); err != nil {
		return nil, err
	}

	// Keep this alive until we're done doing the ioctl dance.
	runtime.KeepAlive(&ifg)

	devices := make([]*wgtypes.Device, 0, len(ifgrs))
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
	dname, err := deviceName(name)
	if err != nil {
		return nil, err
	}

	// First, specify the name of the device and determine how much memory
	// must be allocated in order to store the WGInterfaceIO structure.
	data := wgh.WGDataIO{Name: dname}

	if err := c.ioctlWGDataIO(&data); err != nil {
		// ioctl functions always return a wrapped unix.Errno value.
		// Conform to the wgctrl contract by converting "no such device"
		// to "not exist".
		switch err.(*os.SyscallError).Err {
		case unix.ENXIO:
			return nil, os.ErrNotExist
		default:
			return nil, err
		}
	}

	// Ensure we don't unsafe cast into uninitialized memory.
	if data.Size != wgh.SizeofWGInterfaceIO {
		return nil, fmt.Errorf("wgopenbsd: kernel returned unexpected number of bytes for WGInterfaceIO: %d", data.Size)
	}

	// Allocate the appropriate amount of memory and point the kernel at
	// the first byte of our slice's backing array. Perform the same ioctl
	// again to populate mem with bytes for a WGInterfaceIO.
	mem := make([]byte, data.Size)
	data.Mem = &mem[0]

	if err := c.ioctlWGDataIO(&data); err != nil {
		return nil, err
	}

	// TODO: unpacking of peers, allowed IPs, etc.
	ifio := *(*wgh.WGInterfaceIO)(unsafe.Pointer(data.Mem))

	d := &wgtypes.Device{
		Name:  name,
		Type:  wgtypes.OpenBSDKernel,
		Peers: []wgtypes.Peer{},
	}

	// The kernel populates ifio.Flags to indicate which fields are present.

	if ifio.Flags&wgh.WG_INTERFACE_HAS_PRIVATE != 0 {
		d.PrivateKey = wgtypes.Key(ifio.Private)
	}

	if ifio.Flags&wgh.WG_INTERFACE_HAS_PUBLIC != 0 {
		d.PublicKey = wgtypes.Key(ifio.Public)
	}

	if ifio.Flags&wgh.WG_INTERFACE_HAS_PORT != 0 {
		d.ListenPort = bePort(ifio.Port)
	}

	if ifio.Flags&wgh.WG_INTERFACE_HAS_RTABLE != 0 {
		d.FirewallMark = int(ifio.Rtable)
	}

	return d, nil
}

// ConfigureDevice implements wginternal.Client.
func (c *Client) ConfigureDevice(name string, cfg wgtypes.Config) error {
	// Currently read-only: we must determine if a device belongs to this driver,
	// and if it does, return a sentinel so integration tests that configure a
	// device can be skipped.
	if _, err := c.Device(name); err != nil {
		return err
	}

	return wginternal.ErrReadOnly
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

// bePort interprets a port integer stored in native endianness as a big
// endian value. This is necessary for proper endpoint port handling on
// little endian machines.
func bePort(port uint16) int {
	b := *(*[2]byte)(unsafe.Pointer(&port))
	return int(binary.BigEndian.Uint16(b[:]))
}

// ioctlIfgroupreq returns a function which performs the appropriate ioctl on
// fd to retrieve members of an interface group.
func ioctlIfgroupreq(fd int) func(*wgh.Ifgroupreq) error {
	return func(ifg *wgh.Ifgroupreq) error {
		return ioctl(fd, wgh.SIOCGIFGMEMB, unsafe.Pointer(ifg))
	}
}

// ioctlWGDataIO returns a function which performs the appropriate ioctl on
// fd to issue a WireGuard data I/O.
func ioctlWGDataIO(fd int) func(*wgh.WGDataIO) error {
	return func(data *wgh.WGDataIO) error {
		return ioctl(fd, wgh.SIOCGWG, unsafe.Pointer(data))
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
