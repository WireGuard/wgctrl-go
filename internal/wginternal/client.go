package wginternal

import (
	"fmt"
	"io"
	"runtime"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// A Client is a type which can control a WireGuard device.
type Client interface {
	io.Closer
	Devices() ([]*wgtypes.Device, error)
	Device(name string) (*wgtypes.Device, error)
	ConfigureDevice(name string, cfg wgtypes.Config) error
}

var _ Client = &unimplementedClient{}

// An unimplementedClient is a Client which always returns an error.
type unimplementedClient struct {
	err error
}

// Unimplemented creates a Client that returns a descriptive error when any of
// its methods are invoked.
func Unimplemented(pkg, info string) Client {
	return &unimplementedClient{
		err: fmt.Errorf("%s: not implemented on %s/%s: %s",
			pkg, runtime.GOOS, runtime.GOARCH, info),
	}
}

func (c *unimplementedClient) Close() error                                     { return c.err }
func (c *unimplementedClient) Devices() ([]*wgtypes.Device, error)              { return nil, c.err }
func (c *unimplementedClient) Device(_ string) (*wgtypes.Device, error)         { return nil, c.err }
func (c *unimplementedClient) ConfigureDevice(_ string, _ wgtypes.Config) error { return c.err }
