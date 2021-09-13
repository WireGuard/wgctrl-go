//+build windows

package wgctrl

import (
	"golang.zx2c4.com/wireguard/wgctrl/internal/wginternal"
	"golang.zx2c4.com/wireguard/wgctrl/internal/wgwindows"
	"golang.zx2c4.com/wireguard/wgctrl/internal/wguser"
)

// newClients configures wginternal.Clients for Windows systems.
func newClients() ([]wginternal.Client, error) {
	var clients []wginternal.Client

	// Windows has an in-kernel WireGuard implementation.
	kc := wgwindows.New()
	clients = append(clients, kc)

	uc, err := wguser.New()
	if err != nil {
		return nil, err
	}

	clients = append(clients, uc)
	return clients, nil
}
