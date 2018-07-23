package wireguardctrl

import (
	"errors"
	"io"
	"runtime"

	"github.com/mdlayher/wireguardctrl/wgtypes"
	"github.com/mdlayher/wireguardctrl/wireguardnl"
)

// An osClient is the operating system-specific implementation of Client.
type wgClient interface {
	io.Closer
	Devices() ([]*Device, error)
	DeviceByIndex(index int) (*Device, error)
	DeviceByName(name string) (*Device, error)
}

// TODO(mdlayher): are type aliases the right choice here?

type (
	// A Device is a WireGuard device.
	Device = wgtypes.Device

	// A Peer is a WireGuard peer to a Device.
	Peer = wgtypes.Peer

	// A Key is a public or private key.
	Key = wgtypes.Key
)

// Expose an identical interface to the underlying packages.
var _ wgClient = &Client{}

// A Client provides access to Linux WireGuard netlink information.
type Client struct {
	c wgClient
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

// newClient creates a wgClient based on the current operating system and
// configuration.
func newClient() (wgClient, error) {
	switch runtime.GOOS {
	case "linux":
		return wireguardnl.New()
	default:
		return nil, errors.New("wireguardctrl: userspace configuration protocol not yet implemented")
	}
}

// Close releases resources used by a Client.
func (c *Client) Close() error {
	return c.c.Close()
}

// Devices retrieves all WireGuard devices on this system.
func (c *Client) Devices() ([]*Device, error) {
	return c.c.Devices()
}

// DeviceByIndex retrieves a WireGuard device by its interface index.
//
// If the device specified by index does not exist or is not a WireGuard device,
// an error is returned which can be checked using os.IsNotExist.
func (c *Client) DeviceByIndex(index int) (*Device, error) {
	return c.c.DeviceByIndex(index)
}

// DeviceByName retrieves a WireGuard device by its interface name.
//
// If the device specified by name does not exist or is not a WireGuard device,
// an error is returned which can be checked using os.IsNotExist.
func (c *Client) DeviceByName(name string) (*Device, error) {
	return c.c.DeviceByName(name)
}
