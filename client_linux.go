//+build linux

package wireguardnl

import (
	"fmt"
	"net"
	"os"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"github.com/mdlayher/wireguardnl/internal/wgh"
	"golang.org/x/sys/unix"
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
	// TODO(mdlayher): it doesn't seem possible to do a typical netlink dump
	// of all WireGuard devices.  Perhaps consider raising this to the developers
	// to solicit their feedback.
	ifis, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var ds []*Device
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

	b, err := netlink.MarshalAttributes([]netlink.Attribute{attr})
	if err != nil {
		return nil, err
	}

	msg := genetlink.Message{
		Header: genetlink.Header{
			Command: wgh.CmdGetDevice,
			Version: wgh.GenlVersion,
		},
		Data: b,
	}

	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsDump

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

	if len(msgs) > 1 {
		return nil, fmt.Errorf("wireguardnl: unexpected number of response messages: %d", len(msgs))
	}

	return parseDevice(msgs[0])
}

// parseDevice parses a Device from a generic netlink message.
func parseDevice(m genetlink.Message) (*Device, error) {
	attrs, err := netlink.UnmarshalAttributes(m.Data)
	if err != nil {
		return nil, err
	}

	var d Device
	for _, a := range attrs {
		switch a.Type {
		case wgh.DeviceAIfindex:
			d.Index = int(nlenc.Uint32(a.Data))
		case wgh.DeviceAIfname:
			d.Name = nlenc.String(a.Data)
		case wgh.DeviceAPrivateKey:
			d.PrivateKey = newKey(a.Data)
		case wgh.DeviceAPublicKey:
			d.PublicKey = newKey(a.Data)
		case wgh.DeviceAListenPort:
			d.ListenPort = int(nlenc.Uint16(a.Data))
		case wgh.DeviceAFwmark:
			d.FirewallMark = int(nlenc.Uint32(a.Data))
		}
	}

	return &d, nil
}
