package wireguardctrl

import (
	"io"
	"os"
	"runtime"

	"github.com/mdlayher/wireguardctrl/internal/wgnl"
	"github.com/mdlayher/wireguardctrl/internal/wguser"
	"github.com/mdlayher/wireguardctrl/wgtypes"
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

// A Client provides access to WireGuard device information.
type Client struct {
	// Seamlessly use different wgClient implementations to provide an interface
	// similar to the wg(8).
	cs []wgClient
}

// New creates a new Client.
func New() (*Client, error) {
	cs, err := newClients()
	if err != nil {
		return nil, err
	}

	return &Client{
		cs: cs,
	}, nil
}

// newClients sets up various wgClients based on the current operating system
// and configuration.
func newClients() ([]wgClient, error) {
	var cs []wgClient
	// TODO(mdlayher): smarter detection logic than just the OS in use.
	if runtime.GOOS == "linux" {
		nlc, err := wgnl.New()
		if err != nil {
			return nil, err
		}

		// Netlink devices seem to appear first in wg(8).
		cs = append(cs, nlc)
	}

	cfgc, err := wguser.New()
	if err != nil {
		return nil, err
	}

	cs = append(cs, cfgc)

	return cs, nil
}

// Close releases resources used by a Client.
func (c *Client) Close() error {
	for _, wgc := range c.cs {
		if err := wgc.Close(); err != nil {
			return err
		}
	}

	return nil
}

// Devices retrieves all WireGuard devices on this system.
func (c *Client) Devices() ([]*Device, error) {
	var out []*Device
	for _, wgc := range c.cs {
		devs, err := wgc.Devices()
		if err != nil {
			return nil, err
		}

		out = append(out, devs...)
	}

	return out, nil
}

// DeviceByIndex retrieves a WireGuard device by its interface index.
//
// If the device specified by index does not exist or is not a WireGuard device,
// an error is returned which can be checked using os.IsNotExist.
func (c *Client) DeviceByIndex(index int) (*Device, error) {
	for _, wgc := range c.cs {
		d, err := wgc.DeviceByIndex(index)
		switch {
		case err == nil:
			return d, nil
		case os.IsNotExist(err):
			continue
		default:
			return nil, err
		}
	}

	return nil, os.ErrNotExist
}

// DeviceByName retrieves a WireGuard device by its interface name.
//
// If the device specified by name does not exist or is not a WireGuard device,
// an error is returned which can be checked using os.IsNotExist.
func (c *Client) DeviceByName(name string) (*Device, error) {
	for _, wgc := range c.cs {
		d, err := wgc.DeviceByName(name)
		switch {
		case err == nil:
			return d, nil
		case os.IsNotExist(err):
			continue
		default:
			return nil, err
		}
	}

	return nil, os.ErrNotExist
}
