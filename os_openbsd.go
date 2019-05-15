//+build openbsd

package wgctrl

import (
	"golang.zx2c4.com/wireguard/wgctrl/internal/wginternal"
	"golang.zx2c4.com/wireguard/wgctrl/internal/wgopenbsd"
	"golang.zx2c4.com/wireguard/wgctrl/internal/wguser"
)

// newClients configures wginternal.Clients for OpenBSD systems.
func newClients() ([]wginternal.Client, error) {
	// OpenBSD has an in-kernel WireGuard implementation.
	kc, err := wgopenbsd.New()
	if err != nil {
		return nil, err
	}

	uc, err := wguser.New()
	if err != nil {
		return nil, err
	}

	return []wginternal.Client{kc, uc}, nil
}
