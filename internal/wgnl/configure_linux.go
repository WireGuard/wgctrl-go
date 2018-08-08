//+build linux

package wgnl

import (
	"fmt"
	"net"
	"unsafe"

	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"github.com/mdlayher/wireguardctrl/internal/wgnl/internal/wgh"
	"github.com/mdlayher/wireguardctrl/wgtypes"
	"golang.org/x/sys/unix"
)

// TODO(mdlayher): netlink message chunking with large configurations.

// configAttrs creates the required netlink attributes to configure the device
// specified by name using the non-nil fields in cfg.
func configAttrs(name string, cfg wgtypes.Config) ([]netlink.Attribute, error) {
	var attrs nlAttrs
	attrs.push(wgh.DeviceAIfname, nlenc.Bytes(name))

	if cfg.PrivateKey != nil {
		attrs.push(wgh.DeviceAPrivateKey, (*cfg.PrivateKey)[:])
	}

	if cfg.ListenPort != nil {
		attrs.push(wgh.DeviceAListenPort, nlenc.Uint16Bytes(uint16(*cfg.ListenPort)))
	}

	if cfg.FirewallMark != nil {
		attrs.push(wgh.DeviceAFwmark, nlenc.Uint32Bytes(uint32(*cfg.FirewallMark)))
	}

	if cfg.ReplacePeers {
		attrs.push(wgh.DeviceAFlags, nlenc.Uint32Bytes(wgh.DeviceFReplacePeers))
	}

	var peerArr nlAttrs
	for i, p := range cfg.Peers {
		b, err := peerBytes(p)
		if err != nil {
			return nil, err
		}

		// Netlink arrays use type as an array index.
		peerArr.push(uint16(i), b)
	}

	// Only apply peer attributes if necessary.
	if len(peerArr) > 0 {
		b, err := netlink.MarshalAttributes(peerArr)
		if err != nil {
			return nil, err
		}
		attrs.push(wgh.DeviceAPeers, b)
	}

	return attrs, nil
}

func peerBytes(p wgtypes.PeerConfig) ([]byte, error) {
	var attrs nlAttrs
	attrs.push(wgh.PeerAPublicKey, p.PublicKey[:])

	// Flags are stored in a single attribute.
	var flags uint32
	if p.Remove {
		flags |= wgh.PeerFRemoveMe
	}
	if p.ReplaceAllowedIPs {
		flags |= wgh.PeerFReplaceAllowedips
	}
	if flags != 0 {
		attrs.push(wgh.PeerAFlags, nlenc.Uint32Bytes(flags))
	}

	if p.PresharedKey != nil {
		attrs.push(wgh.PeerAPresharedKey, (*p.PresharedKey)[:])
	}

	if p.Endpoint != nil {
		b, err := sockaddrBytes(*p.Endpoint)
		if err != nil {
			return nil, err
		}

		attrs.push(wgh.PeerAEndpoint, b)
	}

	if p.PersistentKeepaliveInterval != nil {
		attrs.push(wgh.PeerAPersistentKeepaliveInterval, nlenc.Uint16Bytes(uint16(p.PersistentKeepaliveInterval.Seconds())))
	}

	// Only apply allowed IPs if necessary.
	if len(p.AllowedIPs) > 0 {
		b, err := allowedIPBytes(p.AllowedIPs)
		if err != nil {
			return nil, err
		}
		attrs.push(wgh.PeerAAllowedips, b)
	}

	return netlink.MarshalAttributes(attrs)
}

// sockaddrBytes converts a net.UDPAddr to raw sockaddr_in or sockaddr_in6 bytes.
func sockaddrBytes(endpoint net.UDPAddr) ([]byte, error) {
	if !isValidIP(endpoint.IP) {
		return nil, fmt.Errorf("wgnl: invalid endpoint IP: %s", endpoint.IP.String())
	}

	// Is this an IPv6 address?
	if isIPv6(endpoint.IP) {
		var addr [16]byte
		copy(addr[:], endpoint.IP.To16())

		sa := unix.RawSockaddrInet6{
			Family: unix.AF_INET6,
			Port:   uint16(endpoint.Port),
			Addr:   addr,
		}

		return (*(*[unix.SizeofSockaddrInet6]byte)(unsafe.Pointer(&sa)))[:], nil
	}

	// IPv4 address handling.
	var addr [4]byte
	copy(addr[:], endpoint.IP.To4())

	sa := unix.RawSockaddrInet4{
		Family: unix.AF_INET,
		Port:   uint16(endpoint.Port),
		Addr:   addr,
	}

	return (*(*[unix.SizeofSockaddrInet4]byte)(unsafe.Pointer(&sa)))[:], nil
}

// allowedIPBytes converts a slice net.IPNets to packed netlink attribute bytes.
func allowedIPBytes(ipns []net.IPNet) ([]byte, error) {
	var ipArr nlAttrs
	for i, ipn := range ipns {
		if !isValidIP(ipn.IP) {
			return nil, fmt.Errorf("wgnl: invalid allowed IP: %s", ipn.IP.String())
		}

		family := uint16(unix.AF_INET6)
		if !isIPv6(ipn.IP) {
			// Make sure address is 4 bytes if IPv4.
			family = unix.AF_INET
			ipn.IP = ipn.IP.To4()
		}

		var attrs nlAttrs
		attrs.push(wgh.AllowedipAFamily, nlenc.Uint16Bytes(family))

		attrs.push(wgh.AllowedipAIpaddr, ipn.IP)

		ones, _ := ipn.Mask.Size()
		attrs.push(wgh.AllowedipACidrMask, []byte{uint8(ones)})

		b, err := netlink.MarshalAttributes(attrs)
		if err != nil {
			return nil, err
		}

		// Netlink arrays use type as an array index.
		ipArr.push(uint16(i), b)
	}

	return netlink.MarshalAttributes(ipArr)
}

// nlAttrs is a slice of netlink.Attributes.
type nlAttrs []netlink.Attribute

// push adds a new netlink.Attribute with type t and data b.
func (a *nlAttrs) push(t uint16, b []byte) {
	*a = append(*a, netlink.Attribute{
		Type: t,
		Data: b,
	})
}

// isValidIP determines if IP is a valid IPv4 or IPv6 address.
func isValidIP(ip net.IP) bool {
	return ip.To16() != nil
}

// isIPv6 determines if IP is a valid IPv6 address.
func isIPv6(ip net.IP) bool {
	return isValidIP(ip) && ip.To4() == nil
}
