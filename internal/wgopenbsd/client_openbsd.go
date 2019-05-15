//+build openbsd

package wgopenbsd

import (
	"os"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// A client is an OpenBSD-specific WireGuard client.
type client struct {
	fd int
}

// newClient creates a client using a BSD socket.
func newClient() (*client, error) {
	// The OpenBSD ioctl interface operates on a generic AF_INET socket.
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return nil, err
	}

	return &client{
		fd: fd,
	}, nil
}

// Close implements wginternal.Client.
func (c *client) Close() error {
	return unix.Close(c.fd)
}

// Devices implements wginternal.Client.
func (c *client) Devices() ([]*wgtypes.Device, error) {
	// Unimplemented: no devices means this code can be built but is effectively
	// a no-op.
	return nil, nil
}

// Device implements wginternal.Client.
func (c *client) Device(name string) (*wgtypes.Device, error) {
	// Unimplemented: "not exist" error means this code can be built but is
	// effectively a no-op.
	return nil, os.ErrNotExist
}

// ConfigureDevice implements wginternal.Client.
func (c *client) ConfigureDevice(name string, cfg wgtypes.Config) error {
	// Unimplemented: "not exist" error means this code can be built but is
	// effectively a no-op.
	return os.ErrNotExist
}
