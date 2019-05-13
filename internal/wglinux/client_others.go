//+build !linux

package wglinux

import "golang.zx2c4.com/wireguard/wgctrl/internal/wginternal"

// A client is an unimplemented wglinux client.
type client struct {
	wginternal.Client
}

func newClient() (*client, error) {
	return &client{
		Client: wginternal.Unimplemented(
			"wglinux",
			"the WireGuard netlink interface is only available on Linux",
		),
	}, nil
}
