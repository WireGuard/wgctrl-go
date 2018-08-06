// Package wgtypes provides shared types for the wireguardctrl family
// of packages.
package wgtypes

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/curve25519"
)

// A Device is a WireGuard device.
type Device struct {
	Name         string
	PrivateKey   Key
	PublicKey    Key
	ListenPort   int
	FirewallMark int
	Peers        []Peer
}

const keyLen = 32 // wgh.KeyLen

// A Key is a public or private key.
type Key [keyLen]byte

// NewPrivateKey generates a Key containing a private key from a cryptographically
// safe source.
func NewPrivateKey() (Key, error) {
	b := make([]byte, keyLen)
	if _, err := rand.Read(b); err != nil {
		return Key{}, fmt.Errorf("wireguardctrl: failed to read random bytes: %v", err)
	}

	// Modify random bytes using algorithm described at:
	// https://cr.yp.to/ecdh.html.
	b[0] &= 248
	b[31] &= 127
	b[31] |= 64

	key, err := NewKey(b)
	if err != nil {
		return Key{}, fmt.Errorf("wireguardctrl: failed to create key: %v", err)
	}

	return key, nil
}

// NewKey creates a Key from an existing byte slice.  The byte slice must be
// exactly 32 bytes in length.
func NewKey(b []byte) (Key, error) {
	if len(b) != keyLen {
		return Key{}, fmt.Errorf("wireguardctrl: incorrect key size: %d", len(b))
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
		pub  [keyLen]byte
		priv = [keyLen]byte(k)
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
	PublicKey                   Key
	PresharedKey                Key
	Endpoint                    *net.UDPAddr
	PersistentKeepaliveInterval time.Duration
	LastHandshakeTime           time.Time
	ReceiveBytes                int
	TransmitBytes               int
	AllowedIPs                  []net.IPNet
}

// A Config is a WireGuard device configuration.
//
// Because the zero value of some Go types may be significant to WireGuard for
// Config fields, only fields which are not nil will be applied when
// configuring a device.
type Config struct {
	// PrivateKey specifies a private key configuration, if not nil.
	//
	// A non-nil Key will set a new private key.  A non-nil, zero-value, Key
	// will clear the private key.
	PrivateKey *Key
}
