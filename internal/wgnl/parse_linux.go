//+build linux

package wgnl

import (
	"fmt"
	"net"
	"time"
	"unsafe"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/wireguardctrl/internal/wgnl/internal/wgh"
	"github.com/mdlayher/wireguardctrl/wgtypes"
	"golang.org/x/sys/unix"
)

// parseDevice parses a Device from a slice of generic netlink messages,
// automatically merging peer lists from subsequent messages into the Device
// from the first message.
func parseDevice(msgs []genetlink.Message) (*wgtypes.Device, error) {
	var first wgtypes.Device
	for i, m := range msgs {
		d, err := parseDeviceLoop(m)
		if err != nil {
			return nil, err
		}

		if i == 0 {
			// First message contains our target device.
			first = *d
			continue
		}

		// Any subsequent messages have their peer contents merged into the
		// first "target" message.
		if err := mergeDevices(&first, d); err != nil {
			return nil, err
		}
	}

	return &first, nil
}

// parseDeviceLoop parses a Device from a single generic netlink message.
func parseDeviceLoop(m genetlink.Message) (*wgtypes.Device, error) {
	ad, err := netlink.NewAttributeDecoder(m.Data)
	if err != nil {
		return nil, err
	}

	d := wgtypes.Device{
		Type: wgtypes.LinuxKernel,
	}

	for ad.Next() {
		switch ad.Type() {
		case wgh.DeviceAIfindex:
			// Ignored; interface index isn't exposed at all in the userspace
			// configuration protocol, and name is more friendly anyway.
		case wgh.DeviceAIfname:
			d.Name = ad.String()
		case wgh.DeviceAPrivateKey:
			ad.Do(parseKey(&d.PrivateKey))
		case wgh.DeviceAPublicKey:
			ad.Do(parseKey(&d.PublicKey))
		case wgh.DeviceAListenPort:
			d.ListenPort = int(ad.Uint16())
		case wgh.DeviceAFwmark:
			d.FirewallMark = int(ad.Uint32())
		case wgh.DeviceAPeers:
			ad.Do(func(b []byte) error {
				peers, err := parsePeers(b)
				if err != nil {
					return err
				}

				d.Peers = peers
				return nil
			})
		}
	}

	if err := ad.Err(); err != nil {
		return nil, err
	}

	return &d, nil
}

// parsePeers parses a slice of Peers from a netlink attribute payload.
func parsePeers(b []byte) ([]wgtypes.Peer, error) {
	attrs, err := netlink.UnmarshalAttributes(b)
	if err != nil {
		return nil, err
	}

	// This is a netlink "array", so each attribute's data contains more
	// nested attributes for a new Peer.
	ps := make([]wgtypes.Peer, 0, len(attrs))
	for _, a := range attrs {
		ad, err := netlink.NewAttributeDecoder(a.Data)
		if err != nil {
			return nil, err
		}

		var p wgtypes.Peer
		for ad.Next() {
			switch ad.Type() {
			case wgh.PeerAPublicKey:
				ad.Do(parseKey(&p.PublicKey))
			case wgh.PeerAPresharedKey:
				ad.Do(parseKey(&p.PresharedKey))
			case wgh.PeerAEndpoint:
				p.Endpoint = &net.UDPAddr{}
				ad.Do(parseSockaddr(p.Endpoint))
			case wgh.PeerAPersistentKeepaliveInterval:
				// TODO(mdlayher): is this actually in seconds?
				p.PersistentKeepaliveInterval = time.Duration(ad.Uint16()) * time.Second
			case wgh.PeerALastHandshakeTime:
				ad.Do(parseTimespec(&p.LastHandshakeTime))
			case wgh.PeerARxBytes:
				p.ReceiveBytes = int64(ad.Uint64())
			case wgh.PeerATxBytes:
				p.TransmitBytes = int64(ad.Uint64())
			case wgh.PeerAAllowedips:
				ad.Do(func(b []byte) error {
					ipns, err := parseAllowedIPs(b)
					if err != nil {
						return err
					}

					p.AllowedIPs = ipns
					return nil
				})
			case wgh.PeerAProtocolVersion:
				p.ProtocolVersion = int(ad.Uint32())
			}
		}

		if err := ad.Err(); err != nil {
			return nil, err
		}

		ps = append(ps, p)
	}

	return ps, nil
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
		ad, err := netlink.NewAttributeDecoder(a.Data)
		if err != nil {
			return nil, err
		}

		var (
			ipn    net.IPNet
			mask   int
			family int
		)

		for ad.Next() {
			switch ad.Type() {
			case wgh.AllowedipAIpaddr:
				ad.Do(parseAddr(&ipn.IP))
			case wgh.AllowedipACidrMask:
				mask = int(ad.Uint8())
			case wgh.AllowedipAFamily:
				family = int(ad.Uint16())
			}
		}

		if err := ad.Err(); err != nil {
			return nil, err
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

// parseKey parses a wgtypes.Key from a byte slice.
func parseKey(key *wgtypes.Key) func(b []byte) error {
	return func(b []byte) error {
		k, err := wgtypes.NewKey(b)
		if err != nil {
			return err
		}

		*key = k
		return nil
	}
}

// parseAddr parses a net.IP from raw in_addr or in6_addr struct bytes.
func parseAddr(ip *net.IP) func(b []byte) error {
	return func(b []byte) error {
		switch len(b) {
		case net.IPv4len, net.IPv6len:
			// Okay to convert directly to net.IP; memory layout is identical.
			*ip = make(net.IP, len(b))
			copy(*ip, b)
			return nil
		default:
			return fmt.Errorf("wireguardnl: unexpected IP address size: %d", len(b))
		}
	}
}

// parseSockaddr parses a *net.UDPAddr from raw sockaddr_in or sockaddr_in6 bytes.
func parseSockaddr(endpoint *net.UDPAddr) func(b []byte) error {
	return func(b []byte) error {
		switch len(b) {
		case unix.SizeofSockaddrInet4:
			// IPv4 address parsing.
			sa := *(*unix.RawSockaddrInet4)(unsafe.Pointer(&b[0]))

			*endpoint = net.UDPAddr{
				IP:   net.IP(sa.Addr[:]).To4(),
				Port: int(sockaddrPort(int(sa.Port))),
			}

			return nil
		case unix.SizeofSockaddrInet6:
			// IPv6 address parsing.
			sa := *(*unix.RawSockaddrInet6)(unsafe.Pointer(&b[0]))

			*endpoint = net.UDPAddr{
				IP:   net.IP(sa.Addr[:]),
				Port: int(sockaddrPort(int(sa.Port))),
			}

			return nil
		default:
			return fmt.Errorf("wireguardnl: unexpected sockaddr size: %d", len(b))
		}
	}
}

const sizeofTimespec = int(unsafe.Sizeof(unix.Timespec{}))

// parseTimespec parses a time.Time from raw timespec bytes.
func parseTimespec(t *time.Time) func(b []byte) error {
	return func(b []byte) error {
		if len(b) != sizeofTimespec {
			return fmt.Errorf("wireguardnl: unexpected timespec size: %d", len(b))
		}

		// Note: unix.Timespec uses different sized integers on different
		// architectures, so an explicit conversion to int64 is required, even
		// though it isn't needed on amd64.
		ts := *(*unix.Timespec)(unsafe.Pointer(&b[0]))

		// Only set fields if UNIX timestamp value is greater than 0, so the
		// caller will see a zero-value time.Time otherwise.
		if ts.Sec > 0 && ts.Nsec > 0 {
			*t = time.Unix(int64(ts.Sec), int64(ts.Nsec))
		}

		return nil
	}
}

// mergeDevices merges Peer information from d into target.  mergeDevices is
// used to deal with multiple incoming netlink messages for the same device.
func mergeDevices(target, d *wgtypes.Device) error {
	// Peers we are aware already exist in target.
	known := make(map[wgtypes.Key]struct{})
	for _, p := range target.Peers {
		known[p.PublicKey] = struct{}{}
	}

	// Peers which will be added to target if new peers are discovered.
	var peers []wgtypes.Peer

	for j := range target.Peers {
		// Allowed IPs that will be added to target for matching peers.
		var ipns []net.IPNet

		for k := range d.Peers {
			// Does this peer match the current peer?  If so, append its allowed
			// IP networks.
			if target.Peers[j].PublicKey == d.Peers[k].PublicKey {
				ipns = append(ipns, d.Peers[k].AllowedIPs...)
				continue
			}

			// Are we already aware of this peer's existence?  If so, nothing to
			// do here.
			if _, ok := known[d.Peers[k].PublicKey]; ok {
				continue
			}

			// Found a new peer, append it to the output list and mark it as
			// known for future loops.
			peers = append(peers, d.Peers[k])
			known[d.Peers[k].PublicKey] = struct{}{}
		}

		// Add any newly-encountered IPs for this peer.
		target.Peers[j].AllowedIPs = append(target.Peers[j].AllowedIPs, ipns...)
	}

	// Add any newly-encountered peers for this device.
	target.Peers = append(target.Peers, peers...)

	return nil
}
