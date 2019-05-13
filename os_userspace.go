//+build !linux

package wgctrl

import "golang.zx2c4.com/wireguard/wgctrl/internal/wguser"

// newClients configures wgClients for systems which only support userspace
// WireGuard implementations.
func newClients() ([]wgClient, error) {
	c, err := wguser.New()
	if err != nil {
		return nil, err
	}

	return []wgClient{c}, nil
}
