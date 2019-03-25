// Package wgtypes provides shared types for the wireguardctrl family
// of packages.
package wgtypes

import (
	"crypto/rand"
	"encoding"
	"encoding/base64"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/curve25519"
)

// A DeviceType specifies the underlying implementation of a WireGuard device.
type DeviceType int

// Possible DeviceType values.
const (
	Unknown DeviceType = iota
	LinuxKernel
	Userspace
)

// A Device is a WireGuard device.
type Device struct {
	// Name is the name of the device.
	Name string

	// Type specifies the underlying implementation of the device.
	Type DeviceType

	// PrivateKey is the device's private key.
	PrivateKey Key

	// PublicKey is the device's public key, computed from its PrivateKey.
	PublicKey Key

	// ListenPort is the device's network listening port.
	ListenPort int

	// FirewallMark is the device's current firewall mark.
	//
	// The firewall mark can be used in conjunction with firewall software to
	// take action on outgoing WireGuard packets.
	FirewallMark int

	// Peers is the list of network peers associated with this device.
	Peers []Peer
}

// KeyLen is the expected key length for a WireGuard key.
const KeyLen = 32 // wgh.KeyLen

// A Key is a public, private, or pre-shared secret key.  The Key constructor
// functions in this package can be used to create Keys suitable for each of
// these applications.
type Key [KeyLen]byte

// GenerateKey generates a Key suitable for use as a pre-shared secret key from
// a cryptographically safe source.
//
// The output Key should not be used as a private key; use GeneratePrivateKey
// instead.
func GenerateKey() (Key, error) {
	b := make([]byte, KeyLen)
	if _, err := rand.Read(b); err != nil {
		return Key{}, fmt.Errorf("wgtypes: failed to read random bytes: %v", err)
	}

	return NewKey(b)
}

// GeneratePrivateKey generates a Key suitable for use as a private key from a
// cryptographically safe source.
func GeneratePrivateKey() (Key, error) {
	key, err := GenerateKey()
	if err != nil {
		return Key{}, err
	}

	// Modify random bytes using algorithm described at:
	// https://cr.yp.to/ecdh.html.
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64

	return key, nil
}

// NewKey creates a Key from an existing byte slice.  The byte slice must be
// exactly 32 bytes in length.
func NewKey(b []byte) (Key, error) {
	if len(b) != KeyLen {
		return Key{}, fmt.Errorf("wgtypes: incorrect key size: %d", len(b))
	}

	var k Key
	copy(k[:], b)

	return k, nil
}

// PublicKey computes a public key from the private key k.
//
// PublicKey should only be called when k is a private key.
func (k Key) PublicKey() Key {
	var (
		pub  [KeyLen]byte
		priv = [KeyLen]byte(k)
	)

	// ScalarBaseMult uses the correct base value per https://cr.yp.to/ecdh.html,
	// so no need to specify it.
	curve25519.ScalarBaseMult(&pub, &priv)

	return Key(pub)
}

// String returns the base64 string representation of a Key.
func (k Key) String() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

// A Peer is a WireGuard peer to a Device.
type Peer struct {
	// PublicKey is the public key of a peer, computed from its private key.
	//
	// PublicKey is always present in a Peer.
	PublicKey Key

	// PresharedKey is an optional preshared key which may be used as an
	// additional layer of security for peer communications.
	//
	// A zero-value Key means no preshared key is configured.
	PresharedKey Key

	// Endpoint is the most recent source address used for communication by
	// this Peer.
	Endpoint *net.UDPAddr

	// PersistentKeepaliveInterval specifies how often an "empty" packet is sent
	// to a peer to keep a connection alive.
	//
	// A value of 0 indicates that persistent keepalives are disabled.
	PersistentKeepaliveInterval time.Duration

	// LastHandshakeTime indicates the most recent time a handshake was performed
	// with this peer.
	//
	// A zero-value time.Time indicates that no handshake has taken place with
	// this peer.
	LastHandshakeTime time.Time

	// ReceiveBytes indicates the number of bytes received from this peer.
	ReceiveBytes int64

	// TransmitBytes indicates the number of bytes transmitted to this peer.
	TransmitBytes int64

	// AllowedIPs specifies which IPv4 and IPv6 addresses this peer is allowed
	// to communicate on.
	//
	// 0.0.0.0/0 indicates that all IPv4 addresses are allowed, and ::/0
	// indicates that all IPv6 addresses are allowed.
	AllowedIPs []net.IPNet

	// ProtocolVersion specifies which version of the WireGuard protocol is used
	// for this Peer.
	//
	// A value of 0 indicates that the most recent protocol version will be used.
	ProtocolVersion int
}

// A Config is a WireGuard device configuration.
//
// Because the zero value of some Go types may be significant to WireGuard for
// Config fields, pointer types are used for some of these fields. Only
// pointer fields which are not nil will be applied when configuring a device.
type Config struct {
	// list of IP (v4 or v6) addresses (optionally with CIDR masks) to be assigned to the interface. May be specified multiple times.
	Address []net.IPNet

	// list of IP (v4 or v6) addresses to be set as the interface’s DNS servers. May be specified multiple times. Upon bringing the interface up, this runs ‘resolvconf -a tun.INTERFACE -m 0 -x‘ and upon bringing it down, this runs ‘resolvconf -d tun.INTERFACE‘. If these particular invocations of resolvconf(8) are undesirable, the PostUp and PostDown keys below may be used instead.
	DNS []net.IP

	// MTU — if not specified, the MTU is automatically determined from the endpoint addresses or the system default route, which is usually a sane choice. However, to manually specify an MTU to override this automatic discovery, this value may be specified explicitly.
	MTU *int

	// — Controls the routing table to which routes are added. There are two special values: ‘off’ disables the creation of routes altogether, and ‘auto’ (the default) adds routes to the default table and enables special handling of default routes.
	Table *string

	// PreUp, PostUp, PreDown, PostDown — script snippets which will be executed by bash(1) before/after setting up/tearing down the interface, most commonly used to configure custom DNS options or firewall rules. The special string ‘%i’ is expanded to INTERFACE. Each one may be specified multiple times, in which case the commands are executed in order.

	PreUp string
	PostUp string
	PreDown string
	PostDown string

	// SaveConfig — if set to ‘true’, the configuration is saved from the current state of the interface upon shutdown.
	SaveConfig string

	// PrivateKey specifies a private key configuration, if not nil.
	//
	// A non-nil, zero-value, Key will clear the private key.
	PrivateKey *Key

	// ListenPort specifies a device's listening port, if not nil.
	ListenPort *int

	// FirewallMark specifies a device's firewall mark, if not nil.
	//
	// If non-nil and set to 0, the firewall mark will be cleared.
	FirewallMark *int

	// ReplacePeers specifies if the Peers in this configuration should replace
	// the existing peer list, instead of appending them to the existing list.
	ReplacePeers bool

	// Peers specifies a list of peer configurations to apply to a device.
	Peers []PeerConfig
}

// TODO: Implment TextUnmarshaler
var _ encoding.TextMarshaler = (*Config)(nil)

// TODO(mdlayher): consider adding ProtocolVersion in PeerConfig.

// A PeerConfig is a WireGuard device peer configuration.
//
// Because the zero value of some Go types may be significant to WireGuard for
// PeerConfig fields, pointer types are used for some of these fields. Only
// pointer fields which are not nil will be applied when configuring a peer.
type PeerConfig struct {
	// PublicKey specifies the public key of this peer.  PublicKey is a
	// mandatory field for all PeerConfigs.
	PublicKey Key

	// Remove specifies if the peer with this public key should be removed
	// from a device's peer list.
	Remove bool

	// PresharedKey specifies a peer's preshared key configuration, if not nil.
	//
	// A non-nil, zero-value, Key will clear the preshared key.
	PresharedKey *Key

	// Endpoint specifies the endpoint of this peer entry, if not nil.
	Endpoint *net.UDPAddr

	// PersistentKeepaliveInterval specifies the persistent keepalive interval
	// for this peer, if not nil.
	//
	// A non-nil value of 0 will clear the persistent keepalive interval.
	PersistentKeepaliveInterval *time.Duration

	// ReplaceAllowedIPs specifies if the allowed IPs specified in this peer
	// configuration should replace any existing ones, instead of appending them
	// to the allowed IPs list.
	ReplaceAllowedIPs bool

	// AllowedIPs specifies a list of allowed IP addresses in CIDR notation
	// for this peer.
	AllowedIPs []net.IPNet
}
