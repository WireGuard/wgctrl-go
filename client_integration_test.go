//+build integration

package wireguardctrl_test

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/mdlayher/wireguardctrl"
	"github.com/mdlayher/wireguardctrl/internal/wgtest"
	"github.com/mdlayher/wireguardctrl/wgtypes"
	"github.com/mikioh/ipaddr"
)

func TestClientIntegration(t *testing.T) {
	c, err := wireguardctrl.New()
	if err != nil {
		if os.IsNotExist(err) {
			t.Skip("skipping, wireguardctrl is not available on this system")
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
		fn   func(t *testing.T, c *wireguardctrl.Client, devices []*wgtypes.Device)
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Panic if a specific test takes too long.
			timer := time.AfterFunc(20*time.Second, func() {
				panic("test took too long")
			})
			defer timer.Stop()

			tt.fn(t, c, devices)

			// TODO(mdlayher): it seems that wireguard-go doesn't like when
			// the device is "reset".  Investigate and consider resetting
			// it again here later.
		})
	}
}

func testGet(t *testing.T, c *wireguardctrl.Client, devices []*wgtypes.Device) {
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

func testConfigure(t *testing.T, c *wireguardctrl.Client, devices []*wgtypes.Device) {
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
			PrivateKey: priv,
			PublicKey:  priv.PublicKey(),
			ListenPort: port,
			Peers: []wgtypes.Peer{{
				PublicKey:         peerKey,
				LastHandshakeTime: time.Unix(0, 0),
				AllowedIPs:        ips,
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

func testConfigureManyIPs(t *testing.T, c *wireguardctrl.Client, devices []*wgtypes.Device) {
	for _, d := range devices {
		// TODO(mdlayher): apply a second subnet of IPs once potential bug
		// is resolved.

		// Apply 511 IPs.
		cur, err := ipaddr.Parse("2001:db8::/119")
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

		cfg := wgtypes.Config{
			ReplacePeers: true,
			Peers: []wgtypes.PeerConfig{{
				PublicKey:         wgtest.MustPublicKey(),
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

		peerIPs := countPeerIPs(dn)
		if diff := cmp.Diff(len(ips), peerIPs); diff != "" {
			t.Fatalf("unexpected number of configured peer IPs (-want +got):\n%s", diff)
		}

		t.Logf("device: %s: %d IPs", d.Name, peerIPs)
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
