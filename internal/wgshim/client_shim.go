package wgshim

import (
	"fmt"

	"golang.zx2c4.com/wireguard/wgctrl/internal/wginternal"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var _ wginternal.Client = &Client{}

type Client struct {
	wginternal.Client

	probed            bool
	simulateIPRemoval bool
}

func New(c wginternal.Client) *Client {
	return &Client{
		Client: c,
	}
}

func (c *Client) ConfigureDevice(name string, cfg wgtypes.Config) error {
	if !c.probed {
		if supports, err := c.Client.SupportsAllowedIPRemove(name); err != nil {
			return fmt.Errorf("probing capabilities: %w", err)
		} else {
			c.simulateIPRemoval = !supports
		}

		c.probed = true
	}

	if c.simulateIPRemoval {
		devices, err := c.Devices()
		if err != nil {
			return fmt.Errorf("querying devices: %w", err)
		}

		cfg = simulateAllowedIPRemovals(cfg, allowedIPs(device(devices, name)))
	}

	return c.Client.ConfigureDevice(name, cfg)
}

func device(devices []*wgtypes.Device, name string) *wgtypes.Device {
	for _, d := range devices {
		if d.Name == name {
			return d
		}
	}

	return nil
}

func allowedIPs(device *wgtypes.Device) map[wgtypes.Key]map[string]bool {
	aips := make(map[wgtypes.Key]map[string]bool)

	if device != nil {
		for _, peer := range device.Peers {
			aips[peer.PublicKey] = make(map[string]bool)

			for _, aip := range peer.AllowedIPs {
				aips[peer.PublicKey][aip.String()] = true
			}
		}
	}

	return aips
}

func simulateAllowedIPRemovals(cfg wgtypes.Config, current map[wgtypes.Key]map[string]bool) wgtypes.Config {
	newCfg := cfg
	newCfg.Peers = make([]wgtypes.PeerConfig, 0, len(cfg.Peers))

	for _, peer := range cfg.Peers {
		// Keep track if the last instance of each IPNet is a removal.
		removed := make(map[string]bool)
		for _, aip := range peer.AllowedIPs {
			removed[aip.String()] = aip.Remove
		}

		newPeer := peer
		newPeer.AllowedIPs = nil
		dummyPeer := wgtypes.PeerConfig{
			PublicKey: wgtypes.Key{},
		}

		for _, aip := range peer.AllowedIPs {
			if aip.Remove != removed[aip.String()] {
				continue
			}

			if aip.Remove {
				// Do nothing if aip is not currently owned by peer.
				if c := current[peer.PublicKey]; c != nil && c[aip.String()] {
					dummyPeer.AllowedIPs = append(dummyPeer.AllowedIPs, aip)
					dummyPeer.AllowedIPs[len(dummyPeer.AllowedIPs)-1].Remove = false
				}
			} else {
				newPeer.AllowedIPs = append(newPeer.AllowedIPs, aip)
			}
		}

		if len(dummyPeer.AllowedIPs) > 0 {
			newCfg.Peers = append(newCfg.Peers,
				// Move allowed IPs marked with Remove to
				// dummy peer.
				dummyPeer,
				newPeer,
				// Clean up dummy peer.
				wgtypes.PeerConfig{
					PublicKey: wgtypes.Key{},
					Remove:    true,
				})
		} else {
			newCfg.Peers = append(newCfg.Peers, newPeer)
		}
	}

	return newCfg
}
