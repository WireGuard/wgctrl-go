//+build linux

package wgnl

import (
	"encoding/binary"
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

// batchChunk is a tunable allowed IP batch limit per peer.
//
// Because we don't necessarily know how much space a given peer will occupy,
// we play it safe and use a reasonably small value.  Note that this constant
// is used both in this package and tests, so be aware when making changes.
const batchChunk = 256

// shouldBatch determines if the number of peer IP addresses exceeds an
// internal limit for a single message, and thus if the configuration should
// be split into batches.
func shouldBatch(cfg wgtypes.Config) bool {
	var ips int
	for _, p := range cfg.Peers {
		ips += len(p.AllowedIPs)
	}

	return ips > batchChunk
}

// buildBatches produces a batch of configs from a single config, if needed.
func buildBatches(cfg wgtypes.Config) []wgtypes.Config {
	// Is this a small configuration; no need to batch?
	if !shouldBatch(cfg) {
		return []wgtypes.Config{cfg}
	}

	// Use most fields of cfg for our "base" configuration, and only differ
	// peers in each batch.
	base := cfg
	base.Peers = nil

	// Track the known peers so that peer IPs are not replaced if a single
	// peer has its allowed IPs split into multiple batches.
	knownPeers := make(map[wgtypes.Key]struct{})

	batches := make([]wgtypes.Config, 0)
	for _, p := range cfg.Peers {
		batch := base

		// Iterate until no more allowed IPs.
		var done bool
		for !done {
			var tmp []net.IPNet
			if len(p.AllowedIPs) < batchChunk {
				// IPs all fit within a batch; we are done.
				tmp = make([]net.IPNet, len(p.AllowedIPs))
				copy(tmp, p.AllowedIPs)
				done = true
			} else {
				// IPs are larger than a single batch, copy a batch out and
				// advance the cursor.
				tmp = make([]net.IPNet, batchChunk)
				copy(tmp, p.AllowedIPs[:batchChunk])

				p.AllowedIPs = p.AllowedIPs[batchChunk:]

				if len(p.AllowedIPs) == 0 {
					// IPs ended on a batch boundary; no more IPs left so end
					// iteration after this loop.
					done = true
				}
			}

			// Only allow peer IP replacement for the first occurrence of a peer
			// in a batch of configurations, so further IPs can be appended.
			var replaceAllowedIPs bool
			if _, ok := knownPeers[p.PublicKey]; !ok && p.ReplaceAllowedIPs {
				knownPeers[p.PublicKey] = struct{}{}
				replaceAllowedIPs = true
			}

			// Add a peer configuration to this batch and keep going.
			batch.Peers = []wgtypes.PeerConfig{{
				PublicKey:         p.PublicKey,
				ReplaceAllowedIPs: replaceAllowedIPs,
				AllowedIPs:        tmp,
			}}
			batches = append(batches, batch)
		}
	}

	// Do not allow peer replacement beyond the first message in a batch,
	// so we don't overwrite our previous batch work.
	for i := range batches {
		if i > 0 {
			batches[i].ReplacePeers = false
		}
	}

	return batches
}

// peerBytes converts a PeerConfig into netlink attribute bytes.
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
			Port:   binary.BigEndian.Uint16(nlenc.Uint16Bytes(uint16(endpoint.Port))),
			Addr:   addr,
		}

		return (*(*[unix.SizeofSockaddrInet6]byte)(unsafe.Pointer(&sa)))[:], nil
	}

	// IPv4 address handling.
	var addr [4]byte
	copy(addr[:], endpoint.IP.To4())

	sa := unix.RawSockaddrInet4{
		Family: unix.AF_INET,
		Port:   binary.BigEndian.Uint16(nlenc.Uint16Bytes(uint16(endpoint.Port))),
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
