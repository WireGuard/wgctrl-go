package wguser

import (
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/mdlayher/wireguardctrl/wgtypes"
)

// A Client provides access to userspace WireGuard device information.
type Client struct {
	findSockets func() ([]string, error)
}

// New creates a new Client.
func New() (*Client, error) {
	return &Client{
		findSockets: func() ([]string, error) {
			return findSocketFiles([]string{
				// It seems that /var/run is a common location between Linux
				// and the BSDs, even though it's a symlink on Linux.
				"/var/run/wireguard",
			})
		},
	}, nil
}

// Close releases resources used by a Client.
func (c *Client) Close() error { return nil }

// Devices retrieves all WireGuard devices on this system.
func (c *Client) Devices() ([]*wgtypes.Device, error) {
	socks, err := c.findSockets()
	if err != nil {
		return nil, err
	}

	var ds []*wgtypes.Device
	for _, sock := range socks {
		d, err := getDevice(sock)
		if err != nil {
			return nil, err
		}

		ds = append(ds, d)
	}

	return ds, nil
}

// DeviceByIndex retrieves a WireGuard device by its interface index.
//
// If the device specified by index does not exist or is not a WireGuard device,
// an error is returned which can be checked using os.IsNotExist.
func (c *Client) DeviceByIndex(index int) (*wgtypes.Device, error) {
	ifi, err := net.InterfaceByIndex(index)
	if err != nil {
		// Package net doesn't expose a nice way to check this, so we have to
		// improvise just a little bit.
		oerr, ok := err.(*net.OpError)
		if ok && strings.Contains(oerr.Error(), "no such network interface") {
			return nil, os.ErrNotExist
		}

		return nil, err
	}

	return c.DeviceByName(ifi.Name)
}

// DeviceByName retrieves a WireGuard device by its interface name.
//
// If the device specified by name does not exist or is not a WireGuard device,
// an error is returned which can be checked using os.IsNotExist.
func (c *Client) DeviceByName(name string) (*wgtypes.Device, error) {
	socks, err := c.findSockets()
	if err != nil {
		return nil, err
	}

	for _, sock := range socks {
		if name != deviceName(sock) {
			continue
		}

		return getDevice(sock)
	}

	return nil, os.ErrNotExist
}

// deviceName infers a device name from an absolute file path with extension.
func deviceName(sock string) string {
	return strings.TrimSuffix(filepath.Base(sock), filepath.Ext(sock))
}

// findSocketFiles looks for UNIX socket files in the specified directories.
func findSocketFiles(dirs []string) ([]string, error) {
	var socks []string
	for _, d := range dirs {
		files, err := ioutil.ReadDir(d)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}

			return nil, err
		}

		for _, f := range files {
			if f.Mode()&os.ModeSocket == 0 {
				continue
			}

			socks = append(socks, filepath.Join(d, f.Name()))
		}
	}

	return socks, nil
}
