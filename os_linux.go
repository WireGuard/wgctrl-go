//+build linux

package wgctrl

import (
	"golang.zx2c4.com/wireguard/wgctrl/internal/wglinux"
	"golang.zx2c4.com/wireguard/wgctrl/internal/wguser"
)

// newClients configures wgClients for Linux systems.
func newClients() ([]wgClient, error) {
	// Linux has an in-kernel WireGuard implementation.
	nlc, err := wglinux.New()
	if err != nil {
		return nil, err
	}

	// Although it isn't recommended to use userspace implementations on Linux,
	// it can be used. We make use of it in integration tests as well.
	cfgc, err := wguser.New()
	if err != nil {
		return nil, err
	}

	// Netlink devices seem to appear first in wg(8).
	return []wgClient{nlc, cfgc}, nil
}
