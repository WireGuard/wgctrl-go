package wireguardnl

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"time"
)

// A Client provides access to Linux WireGuard netlink information.
type Client struct {
	c osClient
}

// New creates a new Client.
func New() (*Client, error) {
	c, err := newClient()
	if err != nil {
		return nil, err
	}

	return &Client{
		c: c,
	}, nil
}

// Close releases resources used by a Client.
func (c *Client) Close() error {
	return c.c.Close()
}

// Devices retrieves all WireGuard devices on this system.
func (c *Client) Devices() ([]*Device, error) {
	return c.c.Devices()
}

// DeviceByIndex retrieves a WireGuard device by its interface index.
//
// If the device specified by index does not exist or is not a WireGuard device,
// an error is returned which can be checked using os.IsNotExist.
func (c *Client) DeviceByIndex(index int) (*Device, error) {
	return c.c.DeviceByIndex(index)
}

// DeviceByName retrieves a WireGuard device by its interface name.
//
// If the device specified by name does not exist or is not a WireGuard device,
// an error is returned which can be checked using os.IsNotExist.
func (c *Client) DeviceByName(name string) (*Device, error) {
	return c.c.DeviceByName(name)
}

// An osClient is the operating system-specific implementation of Client.
type osClient interface {
	io.Closer
	Devices() ([]*Device, error)
	DeviceByIndex(index int) (*Device, error)
	DeviceByName(name string) (*Device, error)
}

// A Device is a WireGuard device.
type Device struct {
	Index        int
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

// newKey creates a Key from a byte slice.  The byte slice must be exactly
// 32 bytes in length or newKey will panic.
func newKey(b []byte) Key {
	if len(b) != keyLen {
		panic(fmt.Sprintf("wireguardnl: incorrect key size: %d", len(b)))
	}

	var k Key
	copy(k[:], b)

	return k
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
