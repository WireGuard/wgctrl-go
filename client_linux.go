//+build linux

package wireguardnl

import (
	"fmt"
	"net"
	"os"
	"time"
	"unsafe"

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
		case wgh.DeviceAPeers:
			peers, err := parsePeers(a.Data)
			if err != nil {
				return nil, err
			}

			d.Peers = peers
		}
	}

	return &d, nil
}

// parsePeers parses a slice of Peers from a netlink attribute payload.
func parsePeers(b []byte) ([]Peer, error) {
	attrs, err := netlink.UnmarshalAttributes(b)
	if err != nil {
		return nil, err
	}

	// This is a netlink "array", so each attribute's data contains more
	// nested attributes for a new Peer.
	ps := make([]Peer, 0, len(attrs))
	for _, a := range attrs {
		nattrs, err := netlink.UnmarshalAttributes(a.Data)
		if err != nil {
			return nil, err
		}

		var p Peer
		for _, na := range nattrs {
			switch na.Type {
			case wgh.PeerAPublicKey:
				p.PublicKey = newKey(na.Data)
			case wgh.PeerAPresharedKey:
				p.PresharedKey = newKey(na.Data)
			case wgh.PeerAEndpoint:
				p.Endpoint = parseSockaddr(na.Data)
			case wgh.PeerAPersistentKeepaliveInterval:
				// TODO(mdlayher): is this actually in seconds?
				p.PersistentKeepaliveInterval = time.Duration(nlenc.Uint16(na.Data)) * time.Second
			case wgh.PeerALastHandshakeTime:
				p.LastHandshakeTime = parseTimespec(na.Data)
			case wgh.PeerARxBytes:
				p.ReceiveBytes = int(nlenc.Uint64(na.Data))
			case wgh.PeerATxBytes:
				p.TransmitBytes = int(nlenc.Uint64(na.Data))
			case wgh.PeerAAllowedips:
				ipns, err := parseAllowedIPs(na.Data)
				if err != nil {
					return nil, err
				}

				p.AllowedIPs = ipns
			}
		}

		ps = append(ps, p)
	}

	return ps, nil
}

// parseAddr parses a net.IP from raw in_addr or in6_addr struct bytes.
func parseAddr(b []byte) net.IP {
	switch len(b) {
	case net.IPv4len, net.IPv6len:
		// Okay to convert directly to net.IP; memory layout is identical.
		return net.IP(b)
	default:
		panic(fmt.Sprintf("wireguardnl: unexpected IP address size: %d", len(b)))
	}
}

// parseSockaddr parses a *net.UDPAddr from raw sockaddr_in or sockaddr_in6 bytes.
func parseSockaddr(b []byte) *net.UDPAddr {
	switch len(b) {
	case unix.SizeofSockaddrInet4:
		// IPv4 address parsing.
		sa := *(*unix.RawSockaddrInet4)(unsafe.Pointer(&b[0]))

		return &net.UDPAddr{
			IP:   net.IP(sa.Addr[:]).To4(),
			Port: int(sa.Port),
		}
	case unix.SizeofSockaddrInet6:
		// IPv6 address parsing.
		sa := *(*unix.RawSockaddrInet6)(unsafe.Pointer(&b[0]))

		return &net.UDPAddr{
			IP:   net.IP(sa.Addr[:]),
			Port: int(sa.Port),
		}
	default:
		panic(fmt.Sprintf("wireguardnl: unexpected sockaddr size: %d", len(b)))
	}
}

const sizeofTimespec = int(unsafe.Sizeof(unix.Timespec{}))

// parseTimespec parses a time.Time from raw timespec bytes.
func parseTimespec(b []byte) time.Time {
	if len(b) != sizeofTimespec {
		panic(fmt.Sprintf("wireguardnl: unexpected timespec size: %d", len(b)))
	}

	ts := *(*unix.Timespec)(unsafe.Pointer(&b[0]))
	return time.Unix(ts.Sec, ts.Nsec)
}

// parseAllowedIPs parses a slice of net.IPNet from a netlink attribute payload.
func parseAllowedIPs(b []byte) ([]net.IPNet, error) {
	attrs, err := netlink.UnmarshalAttributes(b)
	if err != nil {
		return nil, err
	}

	// This is a netlink "array", so each attribute's data contains more
	// nested attributes for a new net.IPNet.
	ipns := make([]net.IPNet, 0, len(attrs))
	for _, a := range attrs {
		nattrs, err := netlink.UnmarshalAttributes(a.Data)
		if err != nil {
			return nil, err
		}

		var (
			ipn    net.IPNet
			mask   int
			family int
		)

		for _, na := range nattrs {
			switch na.Type {
			case wgh.AllowedipAIpaddr:
				ipn.IP = parseAddr(na.Data)
			case wgh.AllowedipACidrMask:
				mask = int(nlenc.Uint8(na.Data))
			case wgh.AllowedipAFamily:
				family = int(nlenc.Uint16(na.Data))
			}
		}

		// The address family determines the correct number of bits in the mask.
		switch family {
		case unix.AF_INET:
			ipn.Mask = net.CIDRMask(mask, 32)
		case unix.AF_INET6:
			ipn.Mask = net.CIDRMask(mask, 128)
		}

		ipns = append(ipns, ipn)
	}

	return ipns, nil
}
