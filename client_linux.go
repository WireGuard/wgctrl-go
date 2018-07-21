//+build linux

package wireguardnl

import (
	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/wireguardnl/internal/wgh"
)

var _ osClient = &client{}

// A client is a Linux-specific wireguard netlink client.
type client struct {
	c      *genetlink.Conn
	family genetlink.Family
}

// newClient opens a connection to the wireguard family using generic netlink.
func newClient() (*client, error) {
	c, err := genetlink.Dial(nil)
	if err != nil {
		return nil, err
	}

	return initClient(c)
}

// initClient is the internal client constructor used in some tests.
func initClient(c *genetlink.Conn) (*client, error) {
	f, err := c.GetFamily(wgh.GenlName)
	if err != nil {
		_ = c.Close()
		return nil, err
	}

	return &client{
		c:      c,
		family: f,
	}, nil
}

// Close implements osClient.
func (c *client) Close() error {
	return c.c.Close()
}

// Devices implements osClient.
func (c *client) Devices() ([]*Device, error) {
	return nil, nil
}

// DeviceByIndex implements osClient.
func (c *client) DeviceByIndex(index int) (*Device, error) {
	return c.getDevice(index, "")
}

// DeviceByName implements osClient.
func (c *client) DeviceByName(name string) (*Device, error) {
	return c.getDevice(0, name)
}

// getDevice fetches a Device using either its index or name, depending on which
// is specified.  If both are specified, index is preferred.
func (c *client) getDevice(index int, name string) (*Device, error) {
	return nil, nil
}
