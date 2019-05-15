//+build !openbsd

package wgopenbsd

import "golang.zx2c4.com/wireguard/wgctrl/internal/wginternal"

// A client is an unimplemented wgopenbsd client.
type client struct {
	wginternal.Client
}

func newClient() (*client, error) {
	return &client{
		Client: wginternal.Unimplemented(
			"wgopenbsd",
			"the WireGuard ioctl interface is only available on OpenBSD",
		),
	}, nil
}
