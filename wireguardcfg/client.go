package wireguardcfg

import (
	"errors"

	"github.com/mdlayher/wireguardctrl/wgtypes"
)

var (
	errUnimplemented = errors.New("wireguardcfg: userspace configuration protocol not yet implemented")
)

// A Client provides access to userspace WireGuard device information.
type Client struct{}

// New creates a new Client.
func New() (*Client, error) { return nil, errUnimplemented }

// Close releases resources used by a Client.
func (c *Client) Close() error { return errUnimplemented }

// Devices retrieves all WireGuard devices on this system.
func (c *Client) Devices() ([]*wgtypes.Device, error) { return nil, errUnimplemented }

// DeviceByIndex retrieves a WireGuard device by its interface index.
//
// If the device specified by index does not exist or is not a WireGuard device,
// an error is returned which can be checked using os.IsNotExist.
func (c *Client) DeviceByIndex(_ int) (*wgtypes.Device, error) { return nil, errUnimplemented }

// DeviceByName retrieves a WireGuard device by its interface name.
//
// If the device specified by name does not exist or is not a WireGuard device,
// an error is returned which can be checked using os.IsNotExist.
func (c *Client) DeviceByName(_ string) (*wgtypes.Device, error) { return nil, errUnimplemented }
