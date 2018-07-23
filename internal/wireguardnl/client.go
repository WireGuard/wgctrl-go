package wireguardnl

import (
	"io"

	"github.com/mdlayher/wireguardctrl/wgtypes"
)

// A Client provides access to Linux WireGuard netlink information.
type Client struct {
	c osClient
}

// New creates a new Client.
func New() (*Client, error) {
	c, err := newClient()
	if err != nil {
		return nil, err
	}

	return &Client{
		c: c,
	}, nil
}

// Close releases resources used by a Client.
func (c *Client) Close() error {
	return c.c.Close()
}

// Devices retrieves all WireGuard devices on this system.
func (c *Client) Devices() ([]*wgtypes.Device, error) {
	return c.c.Devices()
}

// DeviceByIndex retrieves a WireGuard device by its interface index.
//
// If the device specified by index does not exist or is not a WireGuard device,
// an error is returned which can be checked using os.IsNotExist.
func (c *Client) DeviceByIndex(index int) (*wgtypes.Device, error) {
	return c.c.DeviceByIndex(index)
}

// DeviceByName retrieves a WireGuard device by its interface name.
//
// If the device specified by name does not exist or is not a WireGuard device,
// an error is returned which can be checked using os.IsNotExist.
func (c *Client) DeviceByName(name string) (*wgtypes.Device, error) {
	return c.c.DeviceByName(name)
}

// An osClient is the operating system-specific implementation of Client.
type osClient interface {
	io.Closer
	Devices() ([]*wgtypes.Device, error)
	DeviceByIndex(index int) (*wgtypes.Device, error)
	DeviceByName(name string) (*wgtypes.Device, error)
}
