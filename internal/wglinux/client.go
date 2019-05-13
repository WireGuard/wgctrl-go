package wglinux

import "golang.zx2c4.com/wireguard/wgctrl/internal/wginternal"

var _ wginternal.Client = &client{}

// A Client provides access to Linux WireGuard netlink information.
type Client struct {
	wginternal.Client
}

// New creates a new Client.
func New() (*Client, error) {
	c, err := newClient()
	if err != nil {
		return nil, err
	}

	return &Client{
		Client: c,
	}, nil
}
