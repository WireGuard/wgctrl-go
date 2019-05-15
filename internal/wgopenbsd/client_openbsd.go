//+build openbsd

package wgopenbsd

import (
	"os"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/internal/wginternal"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
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

	// TODO(mdlayher): call Devices or similar here to probe for availability.

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
	// Unimplemented: no devices means this code can be built but is effectively
	// a no-op.
	return nil, nil
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
