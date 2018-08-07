//+build linux

package wgnl

import (
	"net"
	"os"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"github.com/mdlayher/wireguardctrl/internal/wgnl/internal/wgh"
	"github.com/mdlayher/wireguardctrl/wgtypes"
	"golang.org/x/sys/unix"
)

var _ osClient = &client{}

// A client is a Linux-specific wireguard netlink client.
type client struct {
	c      *genetlink.Conn
	family genetlink.Family

	interfaces func() ([]net.Interface, error)
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

		// By default, gather interfaces using package net.
		interfaces: net.Interfaces,
	}, nil
}

// Close implements osClient.
func (c *client) Close() error {
	return c.c.Close()
}

// Devices implements osClient.
func (c *client) Devices() ([]*wgtypes.Device, error) {
	// TODO(mdlayher): consider using rtnetlink directly to fetch only WireGuard
	// devices.  See: https://github.com/mdlayher/wireguardctrl/issues/5.
	ifis, err := c.interfaces()
	if err != nil {
		return nil, err
	}

	var ds []*wgtypes.Device
	for _, ifi := range ifis {
		// Attempt to fetch device information.  If we receive a "not exist"
		// error, the device must not be a WireGuard device.
		d, err := c.getDevice(ifi.Index, ifi.Name)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}

			return nil, err
		}

		ds = append(ds, d)
	}

	return ds, nil
}

// DeviceByIndex implements osClient.
func (c *client) DeviceByIndex(index int) (*wgtypes.Device, error) {
	return c.getDevice(index, "")
}

// DeviceByName implements osClient.
func (c *client) DeviceByName(name string) (*wgtypes.Device, error) {
	return c.getDevice(0, name)
}

// ConfigureDevice implements osClient.
func (c *client) ConfigureDevice(name string, cfg wgtypes.Config) error {
	attrs, err := configAttrs(name, cfg)
	if err != nil {
		return err
	}

	// Request acknowledgement of our request from netlink, even though the
	// output messages are unused.  The netlink package checks and trims the
	// status code value.
	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsAcknowledge
	if _, err := c.execute(wgh.CmdSetDevice, flags, attrs); err != nil {
		return err
	}

	return nil
}

// getDevice fetches a Device using either its index or name, depending on which
// is specified.  If both are specified, index is preferred.
func (c *client) getDevice(index int, name string) (*wgtypes.Device, error) {
	// WireGuard netlink expects either interface index or name for all queries.
	var attr netlink.Attribute
	switch {
	case index != 0:
		attr = netlink.Attribute{
			Type: wgh.DeviceAIfindex,
			Data: nlenc.Uint32Bytes(uint32(index)),
		}
	case name != "":
		attr = netlink.Attribute{
			Type: wgh.DeviceAIfname,
			Data: nlenc.Bytes(name),
		}
	default:
		// No information provided, nothing to do.
		return nil, os.ErrNotExist
	}

	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsDump
	msgs, err := c.execute(wgh.CmdGetDevice, flags, []netlink.Attribute{attr})
	if err != nil {
		return nil, err
	}

	return parseDevice(msgs)
}

// execute executes a single WireGuard netlink request with the specified command,
// header flags, and attribute arguments.
func (c *client) execute(command uint8, flags netlink.HeaderFlags, attrs []netlink.Attribute) ([]genetlink.Message, error) {
	b, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		return nil, err
	}

	msg := genetlink.Message{
		Header: genetlink.Header{
			Command: command,
			Version: wgh.GenlVersion,
		},
		Data: b,
	}

	msgs, err := c.c.Execute(msg, c.family.ID, flags)
	if err != nil {
		switch err {
		// Convert "no such device" and "not a wireguard device" to an error
		// compatible with os.IsNotExist for easy checking.
		case unix.ENODEV, unix.ENOTSUP:
			return nil, os.ErrNotExist
		default:
			return nil, err
		}
	}

	return msgs, nil
}
