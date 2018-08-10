//+build linux

package wgnl

import (
	"fmt"
	"os"
	"syscall"

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

	interfaces func() ([]string, error)
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

		// By default, gather only WireGuard interfaces using rtnetlink.
		interfaces: rtnlInterfaces,
	}, nil
}

// Close implements osClient.
func (c *client) Close() error {
	return c.c.Close()
}

// Devices implements osClient.
func (c *client) Devices() ([]*wgtypes.Device, error) {
	// By default, rtnetlink is used to fetch a list of all interfaces and then
	// filter that list to only find WireGuard interfaces.
	//
	// The remainder of this function assumes that any returned device from this
	// function is a valid WireGuard device.
	ifis, err := c.interfaces()
	if err != nil {
		return nil, err
	}

	var ds []*wgtypes.Device
	for _, ifi := range ifis {
		d, err := c.getDevice(0, ifi)
		if err != nil {
			return nil, err
		}

		ds = append(ds, d)
	}

	return ds, nil
}

// DeviceByName implements osClient.
func (c *client) DeviceByName(name string) (*wgtypes.Device, error) {
	return c.getDevice(0, name)
}

// ConfigureDevice implements osClient.
func (c *client) ConfigureDevice(name string, cfg wgtypes.Config) error {
	// Large configurations are split into batches for use with netlink.
	for _, b := range buildBatches(cfg) {
		attrs, err := configAttrs(name, b)
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

// rtnlInterfaces uses rtnetlink to fetch a list of WireGuard interfaces.
func rtnlInterfaces() ([]string, error) {
	// Use the stdlib's rtnetlink helpers to get ahold of a table of all
	// interfaces, so we can begin filtering it down to just WireGuard devices.
	tab, err := syscall.NetlinkRIB(unix.RTM_GETLINK, unix.AF_UNSPEC)
	if err != nil {
		return nil, fmt.Errorf("wgnl: failed to get list of interfaces from rtnetlink: %v", err)
	}

	msgs, err := syscall.ParseNetlinkMessage(tab)
	if err != nil {
		return nil, fmt.Errorf("wgnl: failed to parse rtnetlink messages: %v", err)
	}

	return parseRTNLInterfaces(msgs)
}

// parseRTNLInterfaces unpacks rtnetlink messages and returns WireGuard
// interface names.
func parseRTNLInterfaces(msgs []syscall.NetlinkMessage) ([]string, error) {
	var ifis []string
	for _, m := range msgs {
		// Only deal with link messages, and they must have an ifinfomsg
		// structure appear before the attributes.
		if m.Header.Type != unix.RTM_NEWLINK {
			continue
		}

		if len(m.Data) < unix.SizeofIfInfomsg {
			return nil, fmt.Errorf("wgnl: rtnetlink message is too short for ifinfomsg: %d", len(m.Data))
		}

		ad, err := netlink.NewAttributeDecoder(m.Data[syscall.SizeofIfInfomsg:])
		if err != nil {
			return nil, err
		}

		// Determine the interface's name and if it's a WireGuard device.
		var (
			ifi  string
			isWG bool
		)

		for ad.Next() {
			switch ad.Type() {
			case unix.IFLA_IFNAME:
				ifi = ad.String()
			case unix.IFLA_LINKINFO:
				ad.Do(isWGKind(&isWG))
			}
		}

		if err := ad.Err(); err != nil {
			return nil, err
		}

		if isWG {
			// Found one; append it to the list.
			ifis = append(ifis, ifi)
		}
	}

	return ifis, nil
}

// wgKind is the IFLA_INFO_KIND value for WireGuard devices.
const wgKind = "wireguard"

// isWGKind parses netlink attributes to determine if a link is a WireGuard
// device, then populates ok with the result.
func isWGKind(ok *bool) func(b []byte) error {
	return func(b []byte) error {
		ad, err := netlink.NewAttributeDecoder(b)
		if err != nil {
			return err
		}

		for ad.Next() {
			if ad.Type() != unix.IFLA_INFO_KIND {
				continue
			}

			if ad.String() == wgKind {
				*ok = true
				return nil
			}
		}

		return ad.Err()
	}
}
