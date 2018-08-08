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
	"github.com/mdlayher/wireguardctrl/wgtypes"
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

	t.Run("get", func(t *testing.T) {
		testGet(t, c, devices)
	})

	t.Run("configure", func(t *testing.T) {
		testConfigure(t, c, devices)
	})
}

func testGet(t *testing.T, c *wireguardctrl.Client, devices []*wgtypes.Device) {
	t.Helper()

	for _, d := range devices {
		t.Logf("device: %s: %s", d.Name, d.PublicKey.String())

		dn, err := c.DeviceByName(d.Name)
		if err != nil {
			t.Fatalf("failed to get %q by name: %v", d.Name, err)
		}

		if diff := cmp.Diff(d, dn); diff != "" {
			t.Fatalf("unexpected Device from DeviceByName (-want +got):\n%s", diff)
		}

		// Fetch the interface index of the device to verify it can be fetched
		// properly by that index.
		ifi, err := net.InterfaceByName(d.Name)
		if err != nil {
			t.Fatalf("failed to get %q network interface: %v", d.Name, err)
		}

		di, err := c.DeviceByIndex(ifi.Index)
		if err != nil {
			t.Fatalf("failed to get %q by index: %v", d.Name, err)
		}

		if diff := cmp.Diff(d, di); diff != "" {
			t.Fatalf("unexpected Device from DeviceByIndex (-want +got):\n%s", diff)
		}
	}
}

func testConfigure(t *testing.T, c *wireguardctrl.Client, devices []*wgtypes.Device) {
	t.Helper()

	for _, d := range devices {
		t.Logf("before: %s: %s", d.Name, d.PublicKey.String())

		priv, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			t.Fatalf("failed to generate private key: %v", err)
		}

		var (
			port    = 8888
			peerKey = mustPublicKey()
			ips     = []net.IPNet{
				mustCIDR("192.0.2.0/24"),
				mustCIDR("2001:db8::/64"),
			}
		)

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

		dn, err := c.DeviceByName(d.Name)
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
			t.Fatalf("unexpected Device from DeviceByName (-want +got):\n%s", diff)
		}

		// Leading space for alignment.
		out := fmt.Sprintf(" after: %s: %s\n", dn.Name, dn.PublicKey.String())
		for _, p := range dn.Peers {
			out += fmt.Sprintf("- peer: %s, IPs: %s\n", p.PublicKey.String(), ipsString(p.AllowedIPs))
		}

		t.Log(out)
	}
}

func ipsString(ipns []net.IPNet) string {
	ss := make([]string, 0, len(ipns))
	for _, ipn := range ipns {
		ss = append(ss, ipn.String())
	}

	return strings.Join(ss, ", ")
}

func mustPublicKey() wgtypes.Key {
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		panicf("failed to generate private key: %v", err)
	}

	return k.PublicKey()
}

func mustCIDR(s string) net.IPNet {
	_, cidr, err := net.ParseCIDR(s)
	if err != nil {
		panicf("failed to parse CIDR: %v", err)
	}

	return *cidr
}

func panicf(format string, a ...interface{}) {
	panic(fmt.Sprintf(format, a...))
}
