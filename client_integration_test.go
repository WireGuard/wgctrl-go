//+build integration

package wgctrl_test

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/mikioh/ipaddr"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/internal/wgtest"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestClientIntegration(t *testing.T) {
	c, err := wgctrl.New()
	if err != nil {
		if os.IsNotExist(err) {
			t.Skip("skipping, wgctrl is not available on this system")
		}

		t.Fatalf("failed to open client: %v", err)
	}
	defer c.Close()

	devices, err := c.Devices()
	if err != nil {
		// It seems that not all errors returned by UNIX socket dialing
		// conform to os.IsPermission, so for now, be lenient and assume that
		// any error here means that permission was denied.
		t.Skipf("skipping, failed to get devices: %v", err)
	}

	tests := []struct {
		name string
		fn   func(t *testing.T, c *wgctrl.Client, devices []*wgtypes.Device)
	}{
		{
			name: "get",
			fn:   testGet,
		},
		{
			name: "configure",
			fn:   testConfigure,
		},
		{
			name: "configure many IPs",
			fn:   testConfigureManyIPs,
		},
		{
			name: "configure many peers",
			fn:   testConfigureManyPeers,
		},
		{
			name: "reset",
			fn: func(t *testing.T, c *wgctrl.Client, devices []*wgtypes.Device) {
				// Reset devices several times; this used to cause a hang in
				// wireguard-go in late 2018.
				for i := 0; i < 10; i++ {
					resetDevices(t, c, devices)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Panic if a specific test takes too long.
			timer := time.AfterFunc(20*time.Second, func() {
				panic("test took too long")
			})
			defer timer.Stop()

			tt.fn(t, c, devices)

			// Start with a clean state after each test.
			resetDevices(t, c, devices)
		})
	}
}

func TestClientIntegrationIsNotExist(t *testing.T) {
	c, err := wgctrl.New()
	if err != nil {
		if os.IsNotExist(err) {
			t.Skip("skipping, wgctrl is not available on this system")
		}

		t.Fatalf("failed to open client: %v", err)
	}
	defer c.Close()

	if _, err := c.Device("wgnotexist0"); !os.IsNotExist(err) {
		t.Fatalf("expected is not exist error, but got: %v", err)
	}
}

func testGet(t *testing.T, c *wgctrl.Client, devices []*wgtypes.Device) {
	for _, d := range devices {
		t.Logf("device: %s: %s", d.Name, d.PublicKey.String())

		dn, err := c.Device(d.Name)
		if err != nil {
			t.Fatalf("failed to get %q: %v", d.Name, err)
		}

		if diff := cmp.Diff(d, dn); diff != "" {
			t.Fatalf("unexpected Device (-want +got):\n%s", diff)
		}
	}
}

func testConfigure(t *testing.T, c *wgctrl.Client, devices []*wgtypes.Device) {
	// Initial values, incremented for each device.
	var (
		port = 8888
		ips  = []net.IPNet{
			wgtest.MustCIDR("192.0.2.0/32"),
			wgtest.MustCIDR("2001:db8::/128"),
		}
	)

	for _, d := range devices {
		t.Logf("before: %s: %s", d.Name, d.PublicKey.String())

		priv, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			t.Fatalf("failed to generate private key: %v", err)
		}

		var (
			peerKey = wgtest.MustPublicKey()
		)

		// Increment some values to avoid collisions.
		port++
		for i := range ips {
			// Increment the last IP byte by 1.
			ips[i].IP[len(ips[i].IP)-1]++
		}

		cfg := wgtypes.Config{
			PrivateKey:   &priv,
			ListenPort:   &port,
			ReplacePeers: true,
			Peers: []wgtypes.PeerConfig{{
				PublicKey:         peerKey,
				ReplaceAllowedIPs: true,
				AllowedIPs:        ips,
			}},
		}

		if err := c.ConfigureDevice(d.Name, cfg); err != nil {
			t.Fatalf("failed to configure %q: %v", d.Name, err)
		}

		dn, err := c.Device(d.Name)
		if err != nil {
			t.Fatalf("failed to get %q by name: %v", d.Name, err)
		}

		// Now that a new configuration has been applied, update our initial
		// device for comparison.
		*d = wgtypes.Device{
			Name:       d.Name,
			Type:       d.Type,
			PrivateKey: priv,
			PublicKey:  priv.PublicKey(),
			ListenPort: port,
			Peers: []wgtypes.Peer{{
				PublicKey:         peerKey,
				LastHandshakeTime: time.Time{},
				AllowedIPs:        ips,
				ProtocolVersion:   1,
			}},
		}

		if diff := cmp.Diff(d, dn); diff != "" {
			t.Fatalf("unexpected Device from Device (-want +got):\n%s", diff)
		}

		// Leading space for alignment.
		out := fmt.Sprintf(" after: %s: %s\n", dn.Name, dn.PublicKey.String())
		for _, p := range dn.Peers {
			out += fmt.Sprintf("- peer: %s, IPs: %s\n", p.PublicKey.String(), ipsString(p.AllowedIPs))
		}

		t.Log(out)
	}
}

func testConfigureManyIPs(t *testing.T, c *wgctrl.Client, devices []*wgtypes.Device) {
	for _, d := range devices {
		// Apply 511 IPs per peer.
		var countIPs int
		var peers []wgtypes.PeerConfig
		for i := 0; i < 2; i++ {
			cidr := "2001:db8::/119"
			if i == 1 {
				cidr = "2001:db8:ffff::/119"
			}

			cur, err := ipaddr.Parse(cidr)
			if err != nil {
				t.Fatalf("failed to create cursor: %v", err)
			}

			var ips []net.IPNet
			for pos := cur.Next(); pos != nil; pos = cur.Next() {
				bits := 128
				if pos.IP.To4() != nil {
					bits = 32
				}

				ips = append(ips, net.IPNet{
					IP:   pos.IP,
					Mask: net.CIDRMask(bits, bits),
				})
			}

			peers = append(peers, wgtypes.PeerConfig{
				PublicKey:         wgtest.MustPublicKey(),
				ReplaceAllowedIPs: true,
				AllowedIPs:        ips,
			})

			countIPs += len(ips)
		}

		cfg := wgtypes.Config{
			ReplacePeers: true,
			Peers:        peers,
		}

		if err := c.ConfigureDevice(d.Name, cfg); err != nil {
			t.Fatalf("failed to configure %q: %v", d.Name, err)
		}

		dn, err := c.Device(d.Name)
		if err != nil {
			t.Fatalf("failed to get %q by name: %v", d.Name, err)
		}

		peerIPs := countPeerIPs(dn)
		if diff := cmp.Diff(countIPs, peerIPs); diff != "" {
			t.Fatalf("unexpected number of configured peer IPs (-want +got):\n%s", diff)
		}

		t.Logf("device: %s: %d IPs", d.Name, peerIPs)
	}
}

func testConfigureManyPeers(t *testing.T, c *wgctrl.Client, devices []*wgtypes.Device) {
	for _, d := range devices {
		const (
			nPeers  = 256
			peerIPs = 512
		)

		var peers []wgtypes.PeerConfig
		for i := 0; i < nPeers; i++ {
			var (
				pk  = wgtest.MustPresharedKey()
				dur = 10 * time.Second
			)

			ips := generateIPs((i + 1) * 2)

			peers = append(peers, wgtypes.PeerConfig{
				PublicKey:         wgtest.MustPublicKey(),
				PresharedKey:      &pk,
				ReplaceAllowedIPs: true,
				Endpoint: &net.UDPAddr{
					IP:   ips[0].IP,
					Port: 1111,
				},
				PersistentKeepaliveInterval: &dur,
				AllowedIPs:                  ips,
			})
		}

		var (
			priv = wgtest.MustPrivateKey()
			n    = 0
		)

		cfg := wgtypes.Config{
			PrivateKey:   &priv,
			ListenPort:   &n,
			FirewallMark: &n,
			ReplacePeers: true,
			Peers:        peers,
		}

		if err := c.ConfigureDevice(d.Name, cfg); err != nil {
			t.Fatalf("failed to configure %q: %v", d.Name, err)
		}

		dn, err := c.Device(d.Name)
		if err != nil {
			t.Fatalf("failed to get updated device: %v", err)
		}

		if diff := cmp.Diff(nPeers, len(dn.Peers)); diff != "" {
			t.Fatalf("unexpected number of peers (-want +got):\n%s", diff)
		}

		countIPs := countPeerIPs(dn)
		if diff := cmp.Diff(peerIPs, countIPs); diff != "" {
			t.Fatalf("unexpected number of peer IPs (-want +got):\n%s", diff)
		}

		t.Logf("device: %s: %d peers, %d IPs", d.Name, len(dn.Peers), countIPs)
	}
}

func resetDevices(t *testing.T, c *wgctrl.Client, devices []*wgtypes.Device) {
	t.Helper()

	zero := 0
	cfg := wgtypes.Config{
		// Clear device config.
		PrivateKey:   &wgtypes.Key{},
		ListenPort:   &zero,
		FirewallMark: &zero,

		// Clear all peers.
		ReplacePeers: true,
	}

	for _, d := range devices {
		if err := c.ConfigureDevice(d.Name, cfg); err != nil {
			t.Fatalf("failed to reset %q: %v", d.Name, err)
		}
	}
}

func countPeerIPs(d *wgtypes.Device) int {
	var count int
	for _, p := range d.Peers {
		count += len(p.AllowedIPs)
	}

	return count
}

func ipsString(ipns []net.IPNet) string {
	ss := make([]string, 0, len(ipns))
	for _, ipn := range ipns {
		ss = append(ss, ipn.String())
	}

	return strings.Join(ss, ", ")
}

func generateIPs(n int) []net.IPNet {
	cur, err := ipaddr.Parse("2001:db8::/64")
	if err != nil {
		panicf("failed to create cursor: %v", err)
	}

	ips := make([]net.IPNet, 0, n)
	for i := 0; i < n; i++ {
		pos := cur.Next()
		if pos == nil {
			panic("hit nil IP during IP generation")
		}

		ips = append(ips, net.IPNet{
			IP:   pos.IP,
			Mask: net.CIDRMask(128, 128),
		})
	}

	return ips
}

func panicf(format string, a ...interface{}) {
	panic(fmt.Sprintf(format, a...))
}
