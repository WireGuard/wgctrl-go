//+build !linux

package wireguardnl

import (
	"fmt"
	"runtime"
)

var (
	// errUnimplemented is returned by all functions on platforms that
	// cannot make use of wireguardnl.
	errUnimplemented = fmt.Errorf("wireguardnl: wireguard netlink not implemented on %s/%s",
		runtime.GOOS, runtime.GOARCH)
)

var _ osClient = &client{}

// A client is an unimplemented wireguardnl client.
type client struct{}

// newClient always returns an error.
func newClient() (*client, error)                        { return nil, errUnimplemented }
func (c *client) Close() error                           { return errUnimplemented }
func (c *client) Devices() ([]*Device, error)            { return nil, errUnimplemented }
func (c *client) DeviceByIndex(_ int) (*Device, error)   { return nil, errUnimplemented }
func (c *client) DeviceByName(_ string) (*Device, error) { return nil, errUnimplemented }
