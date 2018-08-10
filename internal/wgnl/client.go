package wgnl

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

// Close implements wireguardctrl.wgClient.
func (c *Client) Close() error {
	return c.c.Close()
}

// Devices implements wireguardctrl.wgClient.
func (c *Client) Devices() ([]*wgtypes.Device, error) {
	return c.c.Devices()
}

// Device implements wireguardctrl.wgClient.
func (c *Client) Device(name string) (*wgtypes.Device, error) {
	return c.c.Device(name)
}

// ConfigureDevice implements wireguardctrl.wgClient.
func (c *Client) ConfigureDevice(name string, cfg wgtypes.Config) error {
	return c.c.ConfigureDevice(name, cfg)
}

// An osClient is the operating system-specific implementation of Client.
type osClient interface {
	io.Closer
	Devices() ([]*wgtypes.Device, error)
	Device(name string) (*wgtypes.Device, error)
	ConfigureDevice(name string, cfg wgtypes.Config) error
}
